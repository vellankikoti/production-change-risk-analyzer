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
class RiskReport:
    change_id: str
    timestamp: str
    risk_level: RiskLevel
    risk_score: int
    decision: Decision
    evidence: EvidencePackage
    ai_analysis: AIAnalysis
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_id": self.change_id,
            "timestamp": self.timestamp,
            "risk_level": self.risk_level.value if isinstance(self.risk_level, RiskLevel) else self.risk_level,
            "risk_score": self.risk_score,
            "decision": self.decision.value if isinstance(self.decision, Decision) else self.decision,
            "evidence": self.evidence.to_dict(),
            "ai_analysis": self.ai_analysis.to_dict(),
            "reasons": self.reasons,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RiskReport:
        return cls(
            change_id=data["change_id"],
            timestamp=data["timestamp"],
            risk_level=RiskLevel(data["risk_level"]),
            risk_score=data["risk_score"],
            decision=Decision(data["decision"]),
            evidence=EvidencePackage.from_dict(data["evidence"]),
            ai_analysis=AIAnalysis.from_dict(data["ai_analysis"]),
            reasons=data.get("reasons", []),
        )
