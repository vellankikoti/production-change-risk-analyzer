from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ChangeType(str, Enum):
    CREATE = "CREATE"
    MODIFY = "MODIFY"
    DELETE = "DELETE"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Decision(str, Enum):
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"
    APPROVE = "APPROVE"


@dataclass
class ResourceChange:
    resource_id: str
    resource_type: str
    change_type: ChangeType
    before: dict[str, Any] = field(default_factory=dict)
    after: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "change_type": self.change_type.value if isinstance(self.change_type, ChangeType) else self.change_type,
            "before": self.before,
            "after": self.after,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResourceChange:
        return cls(
            resource_id=data["resource_id"],
            resource_type=data["resource_type"],
            change_type=ChangeType(data["change_type"]),
            before=data.get("before", {}),
            after=data.get("after", {}),
        )


@dataclass
class RuleFinding:
    rule_id: str
    severity: Severity
    resource: str
    finding: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    compliance: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value if isinstance(self.severity, Severity) else self.severity,
            "resource": self.resource,
            "finding": self.finding,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "compliance": self.compliance,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RuleFinding:
        return cls(
            rule_id=data["rule_id"],
            severity=Severity(data["severity"]),
            resource=data["resource"],
            finding=data["finding"],
            evidence=data.get("evidence", {}),
            remediation=data.get("remediation", ""),
            compliance=data.get("compliance", []),
        )


@dataclass
class EvidencePackage:
    change_id: str
    timestamp: str
    environment: str
    changes: list[ResourceChange] = field(default_factory=list)
    findings: list[RuleFinding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_id": self.change_id,
            "timestamp": self.timestamp,
            "environment": self.environment,
            "changes": [c.to_dict() for c in self.changes],
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidencePackage:
        return cls(
            change_id=data["change_id"],
            timestamp=data["timestamp"],
            environment=data["environment"],
            changes=[ResourceChange.from_dict(c) for c in data.get("changes", [])],
            findings=[RuleFinding.from_dict(f) for f in data.get("findings", [])],
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def create(cls, environment: str, changes: list[ResourceChange], findings: list[RuleFinding], metadata: dict[str, Any] | None = None) -> EvidencePackage:
        return cls(
            change_id=f"CHG-{uuid.uuid4().hex[:8].upper()}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            environment=environment,
            changes=changes,
            findings=findings,
            metadata=metadata or {},
        )


@dataclass
class AIAnalysis:
    explanation: str = ""
    blast_radius: str = ""
    operational_impact: str = ""
    remediation: str = ""
    confidence: str = ""
    facts: list[str] = field(default_factory=list)
    inferences: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AIAnalysis:
        return cls(
            explanation=data.get("explanation", ""),
            blast_radius=data.get("blast_radius", ""),
            operational_impact=data.get("operational_impact", ""),
            remediation=data.get("remediation", ""),
            confidence=data.get("confidence", ""),
            facts=data.get("facts", []),
            inferences=data.get("inferences", []),
        )

    @classmethod
    def empty(cls) -> AIAnalysis:
        return cls()


@dataclass
class ScoreContribution:
    category: str
    score: int
    findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "score": self.score,
            "findings": self.findings,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScoreContribution:
        return cls(
            category=data["category"],
            score=data["score"],
            findings=data.get("findings", []),
        )


@dataclass
class ScoreBreakdown:
    contributions: list[ScoreContribution] = field(default_factory=list)
    total_score: int = 0
    decision: str = ""
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "contributions": [c.to_dict() for c in self.contributions],
            "total_score": self.total_score,
            "decision": self.decision,
            "explanation": self.explanation,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScoreBreakdown:
        return cls(
            contributions=[ScoreContribution.from_dict(c) for c in data.get("contributions", [])],
            total_score=data.get("total_score", 0),
            decision=data.get("decision", ""),
            explanation=data.get("explanation", ""),
        )


@dataclass
class DependencyEdge:
    source: str
    target: str
    edge_type: str

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "target": self.target, "edge_type": self.edge_type}


@dataclass
class BlastRadius:
    changed_resources: list[str] = field(default_factory=list)
    directly_affected: list[str] = field(default_factory=list)
    transitively_affected: list[str] = field(default_factory=list)
    total_affected: int = 0
    severity: str = "LOW"
    graph: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "changed_resources": self.changed_resources,
            "directly_affected": self.directly_affected,
            "transitively_affected": self.transitively_affected,
            "total_affected": self.total_affected,
            "severity": self.severity,
            "graph": self.graph,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BlastRadius:
        return cls(
            changed_resources=data.get("changed_resources", []),
            directly_affected=data.get("directly_affected", []),
            transitively_affected=data.get("transitively_affected", []),
            total_affected=data.get("total_affected", 0),
            severity=data.get("severity", "LOW"),
            graph=data.get("graph", {}),
        )


@dataclass
class ResourceRollbackRisk:
    resource_id: str
    resource_type: str
    change_type: str
    rollback_risk: str
    reason: str
    may_require_replacement: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "change_type": self.change_type,
            "rollback_risk": self.rollback_risk,
            "reason": self.reason,
            "may_require_replacement": self.may_require_replacement,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResourceRollbackRisk:
        return cls(
            resource_id=data["resource_id"],
            resource_type=data["resource_type"],
            change_type=data["change_type"],
            rollback_risk=data["rollback_risk"],
            reason=data["reason"],
            may_require_replacement=data.get("may_require_replacement", False),
        )


@dataclass
class RollbackAssessment:
    overall_risk: str = "LOW"
    resource_risks: list[ResourceRollbackRisk] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_risk": self.overall_risk,
            "resource_risks": [r.to_dict() for r in self.resource_risks],
            "explanation": self.explanation,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RollbackAssessment:
        return cls(
            overall_risk=data.get("overall_risk", "LOW"),
            resource_risks=[ResourceRollbackRisk.from_dict(r) for r in data.get("resource_risks", [])],
            explanation=data.get("explanation", ""),
        )


@dataclass
class RiskReport:
    change_id: str
    timestamp: str
    risk_level: RiskLevel
    risk_score: int
    decision: Decision
    evidence: EvidencePackage
    ai_analysis: AIAnalysis
    reasons: list[str] = field(default_factory=list)
    score_breakdown: ScoreBreakdown | None = None
    blast_radius: BlastRadius | None = None
    rollback_risk: RollbackAssessment | None = None
    policy_results: list[dict[str, Any]] | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            "change_id": self.change_id,
            "timestamp": self.timestamp,
            "risk_level": self.risk_level.value if isinstance(self.risk_level, RiskLevel) else self.risk_level,
            "risk_score": self.risk_score,
            "decision": self.decision.value if isinstance(self.decision, Decision) else self.decision,
            "evidence": self.evidence.to_dict(),
            "ai_analysis": self.ai_analysis.to_dict(),
            "reasons": self.reasons,
        }
        if self.score_breakdown:
            d["score_breakdown"] = self.score_breakdown.to_dict()
        if self.blast_radius:
            d["blast_radius"] = self.blast_radius.to_dict()
        if self.rollback_risk:
            d["rollback_risk"] = self.rollback_risk.to_dict()
        if self.policy_results:
            d["policy_results"] = self.policy_results
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RiskReport:
        report = cls(
            change_id=data["change_id"],
            timestamp=data["timestamp"],
            risk_level=RiskLevel(data["risk_level"]),
            risk_score=data["risk_score"],
            decision=Decision(data["decision"]),
            evidence=EvidencePackage.from_dict(data["evidence"]),
            ai_analysis=AIAnalysis.from_dict(data["ai_analysis"]),
            reasons=data.get("reasons", []),
        )
        if "score_breakdown" in data:
            report.score_breakdown = ScoreBreakdown.from_dict(data["score_breakdown"])
        if "blast_radius" in data:
            report.blast_radius = BlastRadius.from_dict(data["blast_radius"])
        if "rollback_risk" in data:
            report.rollback_risk = RollbackAssessment.from_dict(data["rollback_risk"])
        if "policy_results" in data:
            report.policy_results = data["policy_results"]
        return report
