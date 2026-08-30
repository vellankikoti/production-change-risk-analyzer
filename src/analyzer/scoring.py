from __future__ import annotations

from collections import defaultdict

from src.models.schemas import Decision, RuleFinding, ScoreBreakdown, ScoreContribution, Severity

RULE_CATEGORIES: dict[str, str] = {
    "IAM": "Identity & Access",
    "SG": "Network Security",
    "NET": "Network Security",
    "AVAIL": "Availability",
    "ENC": "Encryption",
    "LOG": "Logging",
    "S3": "Data Protection",
    "RDS": "Data Protection",
    "DEL": "Data Protection",
}

CATEGORY_SCORE_BASE = {
    Severity.CRITICAL: (25, 5),
    Severity.HIGH: (15, 3),
    Severity.MEDIUM: (8, 2),
    Severity.LOW: (3, 1),
}


def _categorize_rule(rule_id: str) -> str:
    prefix = rule_id.split("-")[0] if "-" in rule_id else rule_id
    return RULE_CATEGORIES.get(prefix, "Other")


def compute_score_breakdown(findings: list[RuleFinding], decision: str = "") -> ScoreBreakdown:
    if not findings:
        return ScoreBreakdown(
            contributions=[],
            total_score=5,
            decision=decision,
            explanation="No rule violations detected",
        )

    by_category: dict[str, list[RuleFinding]] = defaultdict(list)
    for f in findings:
        cat = _categorize_rule(f.rule_id)
        by_category[cat].append(f)

    contributions: list[ScoreContribution] = []
    for cat, cat_findings in sorted(by_category.items(), key=lambda x: x[0]):
        highest_sev = max(
            cat_findings,
            key=lambda f: list(Severity).index(f.severity) if f.severity in list(Severity) else 99,
        )
        highest = highest_sev.severity
        base, per_extra = CATEGORY_SCORE_BASE.get(highest, (3, 1))
        count = len(cat_findings)
        score = base + max(0, count - 1) * per_extra

        descs = [f"{f.rule_id}: {f.finding[:60]}" for f in cat_findings]
        contributions.append(ScoreContribution(
            category=cat,
            score=score,
            findings=descs,
        ))

    contributions.sort(key=lambda c: c.score, reverse=True)
    total = min(100, sum(c.score for c in contributions))

    parts = [f"{c.category} (+{c.score})" for c in contributions if c.score > 0]
    explanation = f"{decision} because: {', '.join(parts)}" if parts else "No findings"

    return ScoreBreakdown(
        contributions=contributions,
        total_score=total,
        decision=decision,
        explanation=explanation,
    )
