# Contributing

Thank you for considering a contribution to the Production Change Risk Analyzer. This guide explains how to add rules, write tests, and submit changes.

## Development Setup

```bash
git clone https://github.com/vellankikoti/production-change-risk-analyzer.git
cd production-change-risk-analyzer
uv venv && source .venv/bin/activate
uv pip install -r requirements.txt
pytest tests/ -v           # All tests should pass
python cli.py eval         # All 7 scenarios should pass
```

## Adding a New Rule

### 1. Create the rule class

Add a new file in `src/rules/` or extend an existing one. Every rule must:
- Extend `src.rules.base.Rule`
- Define `rule_id`, `name`, `description`, `severity`, and `compliance`
- Implement `applies_to(change)` — which resource types this rule checks
- Implement `evaluate(change)` — return a list of `RuleFinding` (empty if no issue)

```python
from src.models.schemas import ResourceChange, RuleFinding, Severity
from src.rules.base import Rule

class MyRule(Rule):
    rule_id = "CATEGORY-NNN"
    name = "Short descriptive name"
    description = "One sentence explaining what this detects"
    severity = Severity.HIGH
    compliance = ["CIS X.Y", "SecurityHub: CONTROL.ID"]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type == "AWS::Service::Resource"

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        # Return findings or empty list
        return []
```

### 2. Register the rule

In `src/analyzer/orchestrator.py`, add your rule to `_build_rule_engine()`:

```python
engine.register(MyRule())
# Or for a new category with multiple rules:
engine.register_all(get_all_my_rules())
```

### 3. Add compliance mappings

Every rule should map to at least one compliance framework:
- **CIS AWS Foundations Benchmark** — section number (e.g., "CIS 1.16")
- **AWS Security Hub** — control ID (e.g., "SecurityHub: IAM.1")
- **AWS Config** — managed rule name (e.g., "AWS Config: restricted-ssh")
- **Well-Architected** — best practice ID (e.g., "Well-Architected: SEC05-BP02")

### 4. Write tests

Create unit tests in `tests/test_rules/`:

```python
def test_my_rule_fires_on_violation():
    change = ResourceChange(...)
    rule = MyRule()
    findings = rule.evaluate(change)
    assert len(findings) == 1
    assert findings[0].rule_id == "CATEGORY-NNN"
    assert findings[0].severity == Severity.HIGH

def test_my_rule_passes_on_compliant():
    change = ResourceChange(...)
    rule = MyRule()
    findings = rule.evaluate(change)
    assert len(findings) == 0
```

### 5. Add an eval scenario

Add an entry to `eval/scenarios.json` with a test fixture that triggers your rule:

```json
{
  "id": "EVAL-NEW",
  "description": "Description of the scenario",
  "before": null,
  "after": "tests/fixtures/templates/my_fixture.yaml",
  "environment": "production",
  "expected_risk_level": "HIGH",
  "expected_decision": "REVIEW",
  "expected_rule_ids": ["CATEGORY-NNN"]
}
```

### 6. Verify

```bash
pytest tests/ -v              # All tests pass
python cli.py eval            # All scenarios pass (including yours)
python cli.py analyze --after tests/fixtures/templates/my_fixture.yaml --no-ai  # Shows your rule
```

## Rule ID Conventions

| Prefix | Category |
|:-------|:---------|
| IAM-   | Identity & access management |
| SG-    | Security groups |
| NET-   | VPC, routing, NACLs |
| AVAIL- | Availability & resilience |
| ENC-   | Encryption at rest |
| LOG-   | Logging & monitoring |
| S3-    | S3-specific data protection |
| RDS-   | RDS-specific data protection |
| DEL-   | Deletion protection |
| ORG-   | Organization-specific (custom) |

## Severity Guidelines

| Severity | When to use |
|:---------|:-----------|
| CRITICAL | Direct security exposure or data loss risk (public DB, admin IAM, no encryption on sensitive data) |
| HIGH | Significant risk that should be reviewed (broad permissions, missing backups, reduced redundancy) |
| MEDIUM | Moderate risk or deviation from best practice (wide port ranges, missing logging) |
| LOW | Informational or minor deviation |

## Running Tests

```bash
pytest tests/ -v                   # All tests
pytest tests/test_rules/ -v        # Rule tests only
pytest tests/test_config.py -v     # Config tests
pytest tests/ -k "test_iam" -v     # Pattern match
python cli.py eval                 # Evaluation scenarios
python cli.py eval --ai            # With AI quality scoring
```

## Pull Request Checklist

- [ ] All existing tests pass (`pytest tests/ -v`)
- [ ] All eval scenarios pass (`python cli.py eval`)
- [ ] New rules have unit tests (positive and negative cases)
- [ ] New rules have compliance mappings
- [ ] New rules have an eval scenario
- [ ] README rules reference table updated (if adding rules)
- [ ] No hardcoded AWS regions or credentials

## Code Style

- Python 3.11+ with type hints
- Dataclasses for data models
- No comments unless the "why" is non-obvious
- Tests use pytest (no unittest.TestCase)
- AWS mocking uses moto

## Reporting Issues

Open an issue on GitHub with:
- What you expected
- What happened instead
- The CloudFormation template (or a minimal reproduction)
- Output of `python cli.py analyze --after template.yaml --no-ai --format json`
