from __future__ import annotations

from abc import ABC, abstractmethod

from src.models.schemas import ResourceChange, RuleFinding, Severity


class Rule(ABC):
    rule_id: str = ""
    name: str = ""
    description: str = ""
    severity: Severity = Severity.INFO

    @abstractmethod
    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        ...

    def applies_to(self, change: ResourceChange) -> bool:
        return True


class RuleEngine:
    def __init__(self) -> None:
        self._rules: list[Rule] = []

    def register(self, rule: Rule) -> None:
        self._rules.append(rule)

    def register_all(self, rules: list[Rule]) -> None:
        self._rules.extend(rules)

    def evaluate(self, changes: list[ResourceChange]) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        for change in changes:
            for rule in self._rules:
                if rule.applies_to(change):
                    findings.extend(rule.evaluate(change))
        return findings

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)
