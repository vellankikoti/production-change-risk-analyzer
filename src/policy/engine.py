from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

DECISION_PRIORITY = {"BLOCK": 3, "REVIEW": 2, "APPROVE": 1}


@dataclass
class Policy:
    id: str
    name: str
    when: dict[str, Any]
    decision: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "when": self.when,
            "decision": self.decision,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        return cls(
            id=data["id"],
            name=data.get("name", data["id"]),
            when=data.get("when", {}),
            decision=data["decision"].upper(),
            reason=data.get("reason", ""),
        )


@dataclass
class PolicyResult:
    policy_id: str
    policy_name: str
    matched: bool
    decision: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "matched": self.matched,
            "decision": self.decision,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyResult:
        return cls(
            policy_id=data["policy_id"],
            policy_name=data["policy_name"],
            matched=data["matched"],
            decision=data["decision"],
            reason=data["reason"],
        )


@dataclass
class PolicyContext:
    """Context object built from analysis results for policy evaluation."""
    environment: str = ""
    resource_types: list[str] = field(default_factory=list)
    change_types: list[str] = field(default_factory=list)
    rules_triggered: list[str] = field(default_factory=list)
    severity_max: str = "LOW"
    risk_score: int = 0
    decision: str = "APPROVE"
    finding_count: int = 0
    resource_ids: list[str] = field(default_factory=list)
    timestamp: str = ""

    @classmethod
    def from_report(cls, report: Any, environment: str = "") -> PolicyContext:
        """Build context from a RiskReport."""
        evidence = report.evidence
        resource_types = list({c.resource_type for c in evidence.changes})
        change_types = list({
            c.change_type.value if hasattr(c.change_type, "value") else c.change_type
            for c in evidence.changes
        })
        rules_triggered = list({f.rule_id for f in evidence.findings})
        resource_ids = [c.resource_id for c in evidence.changes]

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        severity_max = "LOW"
        for f in evidence.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else f.severity
            if severity_order.index(sev) < severity_order.index(severity_max):
                severity_max = sev

        decision_val = report.decision.value if hasattr(report.decision, "value") else report.decision

        return cls(
            environment=environment or evidence.environment,
            resource_types=resource_types,
            change_types=change_types,
            rules_triggered=rules_triggered,
            severity_max=severity_max,
            risk_score=report.risk_score,
            decision=decision_val,
            finding_count=len(evidence.findings),
            resource_ids=resource_ids,
            timestamp=report.timestamp,
        )


class PolicyEngine:
    def __init__(self, policies: list[Policy]) -> None:
        self.policies = policies

    def evaluate(self, context: PolicyContext) -> list[PolicyResult]:
        results = []
        for policy in self.policies:
            matched = self._matches(policy, context)
            results.append(PolicyResult(
                policy_id=policy.id,
                policy_name=policy.name,
                matched=matched,
                decision=policy.decision if matched else "",
                reason=policy.reason if matched else "",
            ))
        return results

    def apply_decision(
        self,
        results: list[PolicyResult],
        base_decision: str,
    ) -> tuple[str, list[PolicyResult]]:
        """Apply policy results to override the base decision.

        Matched policies are sorted by priority. The most restrictive
        matched policy wins (BLOCK > REVIEW > APPROVE).
        A matched APPROVE policy can downgrade a REVIEW but never a BLOCK
        from another policy.
        """
        matched = [r for r in results if r.matched]
        if not matched:
            return base_decision, results

        most_restrictive = base_decision
        for r in matched:
            r_priority = DECISION_PRIORITY.get(r.decision, 0)
            base_priority = DECISION_PRIORITY.get(most_restrictive, 0)
            if r_priority > base_priority:
                most_restrictive = r.decision
            elif r.decision == "APPROVE" and most_restrictive == "REVIEW":
                most_restrictive = "APPROVE"

        return most_restrictive, results

    def _matches(self, policy: Policy, ctx: PolicyContext) -> bool:
        conditions = policy.when
        if not conditions:
            return True

        for key, expected in conditions.items():
            if not self._check_condition(key, expected, ctx):
                return False
        return True

    def _check_condition(self, key: str, expected: Any, ctx: PolicyContext) -> bool:
        if key == "environment":
            if isinstance(expected, list):
                return ctx.environment in expected
            return ctx.environment == expected

        if key == "resource_type":
            if isinstance(expected, list):
                return any(rt in expected for rt in ctx.resource_types)
            return expected in ctx.resource_types

        if key == "change_type":
            if isinstance(expected, list):
                return any(ct in expected for ct in ctx.change_types)
            expected_upper = expected.upper() if isinstance(expected, str) else expected
            return expected_upper in ctx.change_types

        if key == "rules_triggered":
            if isinstance(expected, list):
                return any(r in ctx.rules_triggered for r in expected)
            return expected in ctx.rules_triggered

        if key == "severity_max":
            severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            try:
                ctx_idx = severity_order.index(ctx.severity_max)
                exp_idx = severity_order.index(expected)
                return ctx_idx <= exp_idx
            except ValueError:
                return False

        if key == "risk_score_min":
            return ctx.risk_score >= int(expected)

        if key == "risk_score_max":
            return ctx.risk_score <= int(expected)

        if key == "finding_count_min":
            return ctx.finding_count >= int(expected)

        if key == "resource_id":
            if isinstance(expected, list):
                return any(
                    any(fnmatch.fnmatch(rid, pat) for rid in ctx.resource_ids)
                    for pat in expected
                )
            return any(fnmatch.fnmatch(rid, expected) for rid in ctx.resource_ids)

        # Date-based conditions for change freezes
        if key == "after":
            now = ctx.timestamp or datetime.now(timezone.utc).isoformat()
            return now >= expected

        if key == "before":
            now = ctx.timestamp or datetime.now(timezone.utc).isoformat()
            return now < expected

        logger.warning("Unknown policy condition: %s", key)
        return True

    @classmethod
    def from_yaml(cls, path: str) -> PolicyEngine:
        p = Path(path)
        with open(p) as f:
            data = yaml.safe_load(f) or {}
        policies = [Policy.from_dict(pd) for pd in data.get("policies", [])]
        return cls(policies)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyEngine:
        policies = [Policy.from_dict(pd) for pd in data.get("policies", [])]
        return cls(policies)
