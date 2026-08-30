from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.analyzer.orchestrator import ChangeAnalyzer
from src.models.schemas import RiskReport

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent.parent


@dataclass
class ScenarioResult:
    scenario_id: str
    description: str
    passed: bool
    expected_risk_level: str
    actual_risk_level: str
    expected_decision: str
    actual_decision: str
    expected_rule_ids: list[str]
    actual_rule_ids: list[str]
    missing_rules: list[str]
    extra_rules: list[str]
    risk_level_match: bool
    decision_match: bool
    rules_match: bool
    ai_quality: AIQualityScore | None
    duration_ms: float
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            "scenario_id": self.scenario_id,
            "description": self.description,
            "passed": self.passed,
            "expected_risk_level": self.expected_risk_level,
            "actual_risk_level": self.actual_risk_level,
            "expected_decision": self.expected_decision,
            "actual_decision": self.actual_decision,
            "expected_rule_ids": self.expected_rule_ids,
            "actual_rule_ids": self.actual_rule_ids,
            "missing_rules": self.missing_rules,
            "extra_rules": self.extra_rules,
            "risk_level_match": self.risk_level_match,
            "decision_match": self.decision_match,
            "rules_match": self.rules_match,
            "duration_ms": self.duration_ms,
            "error": self.error,
        }
        if self.ai_quality:
            d["ai_quality"] = self.ai_quality.to_dict()
        return d


@dataclass
class AIQualityScore:
    has_explanation: bool
    has_facts: bool
    has_inferences: bool
    facts_grounded: bool
    no_hallucination_detected: bool
    has_remediation: bool
    has_blast_radius: bool
    structured_output_valid: bool
    score: float  # 0-100

    def to_dict(self) -> dict[str, Any]:
        return {
            "has_explanation": self.has_explanation,
            "has_facts": self.has_facts,
            "has_inferences": self.has_inferences,
            "facts_grounded": self.facts_grounded,
            "no_hallucination_detected": self.no_hallucination_detected,
            "has_remediation": self.has_remediation,
            "has_blast_radius": self.has_blast_radius,
            "structured_output_valid": self.structured_output_valid,
            "score": self.score,
        }


@dataclass
class EvalSummary:
    total: int
    passed: int
    failed: int
    pass_rate: float
    avg_duration_ms: float
    risk_level_accuracy: float
    decision_accuracy: float
    rule_detection_accuracy: float
    avg_ai_quality: float
    results: list[ScenarioResult]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "pass_rate": self.pass_rate,
            "avg_duration_ms": self.avg_duration_ms,
            "risk_level_accuracy": self.risk_level_accuracy,
            "decision_accuracy": self.decision_accuracy,
            "rule_detection_accuracy": self.rule_detection_accuracy,
            "avg_ai_quality": self.avg_ai_quality,
            "results": [r.to_dict() for r in self.results],
        }


def _load_scenarios(path: str | None = None) -> list[dict[str, Any]]:
    p = Path(path) if path else PROJECT_ROOT / "eval" / "scenarios.json"
    with open(p) as f:
        return json.load(f)


def _read_template(path: str | None) -> str | None:
    if not path:
        return None
    full = PROJECT_ROOT / path
    with open(full) as f:
        return f.read()


def _score_ai_quality(report: RiskReport) -> AIQualityScore:
    ai = report.ai_analysis
    has_explanation = bool(ai.explanation and len(ai.explanation) > 10)
    has_facts = bool(ai.facts and len(ai.facts) > 0)
    has_inferences = bool(ai.inferences and len(ai.inferences) > 0)
    has_remediation = bool(ai.remediation and len(ai.remediation) > 10)
    has_blast_radius = bool(ai.blast_radius and len(ai.blast_radius) > 10)

    finding_texts = [f.finding.lower() for f in report.evidence.findings]
    facts_grounded = True
    if ai.facts:
        for fact in ai.facts:
            grounded = any(
                kw in fact.lower()
                for f in report.evidence.findings
                for kw in [f.resource.lower(), str(getattr(f, 'rule_id', '')).lower()]
                if kw
            )
            if not grounded:
                grounded = any(
                    w in fact.lower()
                    for w in ["port", "cidr", "iam", "capacity", "multi-az", "backup", "security group", "0.0.0.0"]
                )
            if not grounded:
                facts_grounded = False
                break

    no_hallucination = True
    if ai.explanation:
        hallucination_signals = ["i don't have", "i cannot", "as an ai", "i'm not sure"]
        no_hallucination = not any(s in ai.explanation.lower() for s in hallucination_signals)

    structured_valid = bool(ai.explanation) and bool(ai.confidence)

    checks = [
        has_explanation, has_facts, has_inferences, facts_grounded,
        no_hallucination, has_remediation, has_blast_radius, structured_valid
    ]
    score = sum(checks) / len(checks) * 100

    return AIQualityScore(
        has_explanation=has_explanation,
        has_facts=has_facts,
        has_inferences=has_inferences,
        facts_grounded=facts_grounded,
        no_hallucination_detected=no_hallucination,
        has_remediation=has_remediation,
        has_blast_radius=has_blast_radius,
        structured_output_valid=structured_valid,
        score=score,
    )


def run_evaluation(
    scenarios_path: str | None = None,
    use_ai: bool = False,
    verbose: bool = False,
) -> EvalSummary:
    scenarios = _load_scenarios(scenarios_path)
    analyzer = ChangeAnalyzer(use_ai=use_ai)
    results: list[ScenarioResult] = []

    for scenario in scenarios:
        sid = scenario["id"]
        if verbose:
            logger.info("Running scenario %s: %s", sid, scenario["description"])

        start = time.monotonic()
        error = None
        try:
            before = _read_template(scenario.get("before"))
            after = _read_template(scenario["after"])
            report = analyzer.analyze(
                after_template=after,
                before_template=before,
                environment=scenario.get("environment", "development"),
            )
        except Exception as e:
            error = str(e)
            report = None
        elapsed = (time.monotonic() - start) * 1000

        if report is None:
            results.append(ScenarioResult(
                scenario_id=sid,
                description=scenario["description"],
                passed=False,
                expected_risk_level=scenario["expected_risk_level"],
                actual_risk_level="ERROR",
                expected_decision=scenario["expected_decision"],
                actual_decision="ERROR",
                expected_rule_ids=scenario.get("expected_rule_ids", []),
                actual_rule_ids=[],
                missing_rules=scenario.get("expected_rule_ids", []),
                extra_rules=[],
                risk_level_match=False,
                decision_match=False,
                rules_match=False,
                ai_quality=None,
                duration_ms=elapsed,
                error=error,
            ))
            continue

        actual_rl = report.risk_level.value
        actual_dec = report.decision.value
        actual_rule_ids = list({f.rule_id for f in report.evidence.findings})

        expected_rules = set(scenario.get("expected_rule_ids", []))
        actual_rules_set = set(actual_rule_ids)
        missing_rules = sorted(expected_rules - actual_rules_set)
        extra_rules = sorted(actual_rules_set - expected_rules)

        rl_match = actual_rl == scenario["expected_risk_level"]
        dec_match = actual_dec == scenario["expected_decision"]
        rules_match = expected_rules.issubset(actual_rules_set)

        ai_quality = _score_ai_quality(report) if use_ai and report.evidence.findings else None

        passed = rl_match and dec_match and rules_match

        results.append(ScenarioResult(
            scenario_id=sid,
            description=scenario["description"],
            passed=passed,
            expected_risk_level=scenario["expected_risk_level"],
            actual_risk_level=actual_rl,
            expected_decision=scenario["expected_decision"],
            actual_decision=actual_dec,
            expected_rule_ids=sorted(expected_rules),
            actual_rule_ids=sorted(actual_rule_ids),
            missing_rules=missing_rules,
            extra_rules=extra_rules,
            risk_level_match=rl_match,
            decision_match=dec_match,
            rules_match=rules_match,
            ai_quality=ai_quality,
            duration_ms=elapsed,
            error=error,
        ))

    total = len(results)
    passed = sum(1 for r in results if r.passed)
    rl_correct = sum(1 for r in results if r.risk_level_match)
    dec_correct = sum(1 for r in results if r.decision_match)
    rules_correct = sum(1 for r in results if r.rules_match)
    ai_scores = [r.ai_quality.score for r in results if r.ai_quality]

    return EvalSummary(
        total=total,
        passed=passed,
        failed=total - passed,
        pass_rate=round(passed / total * 100, 1) if total else 0,
        avg_duration_ms=round(sum(r.duration_ms for r in results) / total, 1) if total else 0,
        risk_level_accuracy=round(rl_correct / total * 100, 1) if total else 0,
        decision_accuracy=round(dec_correct / total * 100, 1) if total else 0,
        rule_detection_accuracy=round(rules_correct / total * 100, 1) if total else 0,
        avg_ai_quality=round(sum(ai_scores) / len(ai_scores), 1) if ai_scores else 0,
        results=results,
    )
