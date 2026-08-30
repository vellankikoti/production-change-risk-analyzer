# Production Change Risk Analyzer

**Detect risky CloudFormation changes before they reach production.** Deterministic rules catch known patterns. AI explains what the rules found — it never decides BLOCK or APPROVE.

[![CI](https://github.com/vellankikoti/production-change-risk-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/vellankikoti/production-change-risk-analyzer/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## How It Works

```
CloudFormation Template  ─→  Parser  ─→  18 Deterministic Rules  ─→  Evidence Package  ─→  AI Explanation  ─→  Risk Report
                                              │                              │                                      │
                                              │  IAM, Security Groups,       │  FACT vs INFERENCE                   │  BLOCK / REVIEW / APPROVE
                                              │  Network, Availability       │  separation enforced                 │  (threshold-based, not AI)
                                              └──────────────────────────────┘──────────────────────────────────────┘
```

**Key design principle:** The AI layer only explains risks using evidence the rules found. It never invents findings and never makes the BLOCK/APPROVE decision — deterministic thresholds do.

| Finding Severity | Decision | Score Range |
|:----------------|:---------|:------------|
| Any CRITICAL    | BLOCK    | 80-100      |
| Any HIGH        | REVIEW   | 60-79       |
| Only MEDIUM     | REVIEW   | 40-59       |
| Only LOW/INFO   | APPROVE  | 0-39        |

---

## Quick Start

### Prerequisites

- Python 3.11+
- AWS CLI configured with credentials (for AI analysis and AWS integrations)
- [uv](https://docs.astral.sh/uv/) package manager (recommended) or pip

### Install

```bash
git clone https://github.com/vellankikoti/production-change-risk-analyzer.git
cd production-change-risk-analyzer
uv venv && source .venv/bin/activate
uv pip install -r requirements.txt
```

### Analyze Your First Template

```bash
# Analyze a new stack
python cli.py analyze --after your-template.yaml

# Compare before/after changes
python cli.py analyze --before current.yaml --after proposed.yaml --environment production

# Deterministic rules only (no AI, no AWS credentials needed for rules)
python cli.py analyze --after your-template.yaml --no-ai
```

### Output Formats

```bash
# Rich terminal output (default)
python cli.py analyze --after template.yaml

# JSON (for programmatic consumption)
python cli.py analyze --after template.yaml --format json

# SARIF (for GitHub Security tab)
python cli.py analyze --after template.yaml --format sarif --output-file results.sarif

# Markdown (for PR comments)
python cli.py analyze --after template.yaml --format markdown

# JUnit XML (for CI test reporting)
python cli.py analyze --after template.yaml --format junit --output-file results.xml
```

---

## Rules Reference

18 rules across 4 categories, each mapped to compliance frameworks.

### IAM Rules

| Rule | Description | Severity | Compliance |
|:-----|:-----------|:---------|:-----------|
| IAM-001 | Wildcard actions (`*`) in IAM policies | CRITICAL | CIS 1.16, SecurityHub IAM.1 |
| IAM-002 | Wildcard resources (`*`) | HIGH | CIS 1.16, SecurityHub IAM.1 |
| IAM-003 | Combined wildcard action + resource (full admin) | CRITICAL | CIS 1.16, SecurityHub IAM.1 |
| IAM-004 | Privilege escalation patterns (iam:PassRole, sts:AssumeRole *) | HIGH | CIS 1.16, SecurityHub IAM.1 |
| IAM-005 | Overly broad data access (s3:*, dynamodb:*) | MEDIUM | CIS 1.16, Well-Architected SEC03-BP07 |

### Security Group Rules

| Rule | Description | Severity | Compliance |
|:-----|:-----------|:---------|:-----------|
| SG-001 | Public access to sensitive ports (SSH, RDP, databases) | CRITICAL | CIS 5.2/5.3, SecurityHub EC2.19 |
| SG-002 | Unrestricted ingress from 0.0.0.0/0 | MEDIUM | CIS 5.2, SecurityHub EC2.18 |
| SG-003 | Port ranges wider than 100 ports | MEDIUM | Well-Architected SEC05-BP02 |
| SG-004 | All traffic (protocol -1) from any source | CRITICAL | CIS 5.2/5.3, SecurityHub EC2.19 |

### Network Rules

| Rule | Description | Severity | Compliance |
|:-----|:-----------|:---------|:-----------|
| NET-001 | Subnet associated with route table that has IGW route | HIGH | CIS 5.1, Well-Architected SEC05-BP01 |
| NET-002 | NAT Gateway deletion (breaks private subnet internet) | HIGH | Well-Architected REL02-BP01 |
| NET-003 | NACL allows all inbound from 0.0.0.0/0 | MEDIUM | CIS 5.1, SecurityHub EC2.21 |
| NET-004 | Route sending 0.0.0.0/0 to Internet Gateway | HIGH | CIS 5.1, Well-Architected SEC05-BP01 |

### Availability Rules

| Rule | Description | Severity | Compliance |
|:-----|:-----------|:---------|:-----------|
| AVAIL-001 | ASG desired capacity reduction | MEDIUM | Well-Architected REL06-BP01 |
| AVAIL-002 | ASG min capacity below 2 | HIGH | Well-Architected REL10-BP01 |
| AVAIL-003 | Multi-AZ disabled on RDS | CRITICAL | SecurityHub RDS.5, Well-Architected REL10-BP01 |
| AVAIL-004 | Deletion of critical resources (RDS, DynamoDB, ECS, EKS, ElastiCache) | CRITICAL | Well-Architected OPS08-BP01 |
| AVAIL-005 | Backup retention reduced to 0 | HIGH | SecurityHub RDS.11, Well-Architected REL09-BP01 |

---

## AI Analysis: FACT vs INFERENCE

When AI is enabled, the analyzer calls Amazon Bedrock to explain findings. The AI output is strictly structured:

- **FACTS** — directly observable from the evidence (e.g., "Port 5432 is configured with CIDR 0.0.0.0/0")
- **INFERENCES** — conclusions drawn from facts (e.g., "The database could be reachable from the public internet")

The AI also provides blast radius assessment, operational impact, and remediation steps. If AI is unavailable, the tool degrades gracefully — deterministic rules still produce a complete risk report.

```
AI model: amazon.nova-lite-v1:0 (configurable)
Retry: Exponential backoff on throttling (3 attempts)
Token protection: Evidence truncated to 15K chars if oversized
```

---

## Configuration

Create a `risk-analyzer.yaml` in your project root:

```yaml
# Risk scoring thresholds
thresholds:
  critical_min: 80
  high_min: 60
  medium_min: 40

# AI configuration
ai:
  enabled: true
  model_id: amazon.nova-lite-v1:0
  max_tokens: 2048

# Per-environment overrides
environments:
  production:
    thresholds:
      critical_min: 70   # Stricter in production
      high_min: 50
  development:
    rule_overrides:
      SG-002:
        enabled: false    # Allow unrestricted ingress in dev

# Suppression (accepted risks with audit trail)
suppressions:
  - rule_id: SG-001
    resource_pattern: "DevSecurityGroup"
    reason: "Accepted risk — ticket SEC-1234"
    expires: "2025-12-31T00:00:00Z"
```

See [`risk-analyzer.yaml`](risk-analyzer.yaml) for the full annotated default config.

---

## CI/CD Integration

### GitHub Actions

Copy `.github/workflows/risk-analyze.yml` to your repository. It automatically:

1. Detects CloudFormation file changes in PRs
2. Runs deterministic risk analysis on each changed file
3. Uploads SARIF results to GitHub Security tab
4. Posts a Markdown risk report as a PR comment
5. Blocks the PR if any file triggers a BLOCK decision

**Required setup:**
- Add `AWS_REGION` as a repository variable (or it defaults to `us-west-2`)
- For AI analysis, configure AWS credentials as repository secrets

### Any CI System

```bash
# Exit code: 0 = APPROVE, 1 = BLOCK or REVIEW
python cli.py analyze \
  --before baseline.yaml \
  --after proposed.yaml \
  --environment production \
  --no-ai \
  --format sarif \
  --output-file results.sarif

# Use in a pipeline gate
if python cli.py analyze --after proposed.yaml --no-ai --format json 2>/dev/null | python -c "import sys,json; sys.exit(0 if json.load(sys.stdin)['decision']=='APPROVE' else 1)"; then
  echo "Changes approved"
else
  echo "Changes need review or are blocked"
fi
```

### AWS CodeBuild

See [`ci/buildspec.yaml`](ci/buildspec.yaml) for a ready-to-use buildspec and [`ci/codebuild-project.yaml`](ci/codebuild-project.yaml) for the CloudFormation project template.

---

## AWS Integrations (Optional)

All AWS integrations are optional. The core analyzer works without any AWS services.

### DynamoDB — Report Storage

```bash
# Store analysis reports for audit trail
python cli.py analyze --after template.yaml --save

# Retrieve a report
python cli.py report CHG-A1B2C3D4

# List recent reports
python cli.py list --risk-level CRITICAL --limit 10

# View trends
python cli.py trending
```

### S3 — Evidence Archival

```bash
# Save evidence packages and templates to S3
python cli.py analyze --before current.yaml --after proposed.yaml --save-evidence
```

### SNS — Notifications

```bash
# Send SNS alert for HIGH/CRITICAL findings
python cli.py analyze --after template.yaml --notify

# Subscribe to alerts
python cli.py subscribe your-email@company.com
```

### CloudWatch — Metrics & Dashboard

```bash
# Create the CloudWatch dashboard (8 widgets)
python cli.py dashboard

# Metrics published automatically: AnalysisCount, RiskScore, FindingCount,
# AnalysisDuration, Decision_*, RiskLevel_*, RuleTriggerCount, FindingsBySeverity
```

### Infrastructure Setup

```bash
# Option 1: CloudFormation
aws cloudformation deploy \
  --template-file infra/risk-analyzer-infra.yaml \
  --stack-name risk-analyzer-dev \
  --parameter-overrides Environment=dev \
  --capabilities CAPABILITY_NAMED_IAM

# Option 2: Manual (AWS CLI)
source setup-env.sh  # Sets environment variables for table, bucket, topic
```

---

## Web Dashboard

```bash
python web_server.py
# Opens at http://localhost:8501
```

Features:
- Upload templates for analysis
- View historical reports with risk distribution
- Quick-test buttons for fixture templates
- Full report view with AI analysis, facts, and inferences

---

## Evaluation Framework

6 built-in scenarios validate that rules fire correctly and risk levels match expectations.

```bash
# Run evaluation (deterministic)
python cli.py eval

# With AI quality scoring
python cli.py eval --ai

# JSON output for CI
python cli.py eval --json-output
```

Evaluation checks:
- Risk level accuracy (expected vs actual)
- Decision accuracy (BLOCK/REVIEW/APPROVE)
- Rule detection accuracy (expected rule IDs fire)
- AI quality (8 dimensions: explanation, facts, inferences, grounding, hallucination, remediation, blast radius, structured output)

---

## Adding Custom Rules

Create a rule class that extends `Rule`:

```python
from src.models.schemas import ChangeType, ResourceChange, RuleFinding, Severity
from src.rules.base import Rule

class MyCustomRule(Rule):
    rule_id = "CUSTOM-001"
    name = "My Custom Check"
    description = "Detects something specific to my organization"
    severity = Severity.HIGH
    compliance = ["Internal-Policy-42"]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type == "AWS::SomeService::SomeResource"

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        props = change.after or {}
        if some_condition(props):
            return [RuleFinding(
                rule_id=self.rule_id,
                severity=self.severity,
                resource=change.resource_id,
                finding="Description of what was detected",
                evidence={"key": "value"},
                remediation="How to fix it",
            )]
        return []
```

Register it in `src/analyzer/orchestrator.py`:

```python
from my_rules import MyCustomRule

def _build_rule_engine() -> RuleEngine:
    engine = RuleEngine()
    engine.register_all(get_all_iam_rules())
    engine.register_all(get_all_sg_rules())
    engine.register_all(get_all_network_rules())
    engine.register_all(get_all_availability_rules())
    engine.register(MyCustomRule())  # Add your rule
    return engine
```

---

## Risk Scoring Formula

The scoring is fully deterministic — no AI involvement:

1. **Severity mapping:** Each finding has a severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
2. **Highest severity wins:** The highest severity finding determines the risk level
3. **Score calculation:**
   - CRITICAL: `80 + (critical_count * 5)`, capped at 100
   - HIGH: `60 + (high_count * 5)`, capped at 79
   - MEDIUM: `40 + (medium_count * 5)`, capped at 59
   - LOW: `10 + (low_count * 5)`, capped at 39
   - No findings: score 5
4. **Decision:** Score maps to BLOCK (>=80), REVIEW (40-79), or APPROVE (<40)

---

## Project Structure

```
production-change-risk-analyzer/
├── cli.py                    # Click CLI with analyze, report, list, eval, trending
├── web_server.py             # FastAPI web dashboard launcher
├── risk-analyzer.yaml        # Default configuration
├── requirements.txt
├── src/
│   ├── analyzer/
│   │   └── orchestrator.py   # Main orchestrator (ties rules + AI + scoring)
│   ├── ai/
│   │   └── bedrock_analyzer.py  # Bedrock integration with retry and token protection
│   ├── config.py             # YAML configuration loader with env overrides
│   ├── models/
│   │   └── schemas.py        # Data models (ResourceChange, RuleFinding, RiskReport)
│   ├── output/
│   │   ├── sarif.py          # SARIF 2.1.0 output (GitHub Security tab)
│   │   ├── markdown.py       # Markdown output (PR comments)
│   │   └── junit.py          # JUnit XML output (CI test reporting)
│   ├── parser/
│   │   └── cloudformation.py # CloudFormation YAML/JSON parser with intrinsic functions
│   ├── rules/
│   │   ├── base.py           # Rule ABC and RuleEngine
│   │   ├── iam.py            # IAM-001 through IAM-005
│   │   ├── security_group.py # SG-001 through SG-004
│   │   ├── network.py        # NET-001 through NET-004
│   │   └── availability.py   # AVAIL-001 through AVAIL-005
│   ├── evaluation/
│   │   └── runner.py         # Evaluation framework (6 scenarios, 8 AI quality dimensions)
│   ├── notifications/
│   │   └── sns.py            # SNS notifications for HIGH/CRITICAL
│   ├── observability/
│   │   ├── metrics.py        # CloudWatch custom metrics
│   │   └── dashboard.py      # CloudWatch dashboard (8 widgets)
│   ├── storage/
│   │   ├── dynamodb.py       # Report storage (PK=change_id, GSI on risk_level)
│   │   └── s3.py             # Evidence archival with versioning
│   └── web/
│       ├── app.py            # FastAPI application
│       └── templates/        # Jinja2 templates (dashboard, analyze, report)
├── tests/
│   ├── test_rules/           # 47 unit tests
│   ├── test_analyzer/
│   └── test_output/
├── eval/
│   └── scenarios.json        # 6 evaluation scenarios
├── ci/
│   ├── buildspec.yaml        # AWS CodeBuild buildspec
│   ├── codebuild-project.yaml
│   └── run-local.sh
├── infra/
│   └── risk-analyzer-infra.yaml  # CloudFormation for DynamoDB, S3, SNS
└── .github/
    └── workflows/
        ├── risk-analyze.yml  # PR risk analysis workflow
        └── ci.yml            # Test and eval CI
```

---

## Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test category
pytest tests/test_rules/ -v
pytest tests/test_analyzer/ -v
pytest tests/test_output/ -v

# Run evaluation
python cli.py eval
```

---

## Compliance Framework Mapping

Every rule maps to one or more compliance frameworks:

- **CIS AWS Foundations Benchmark** — Identity, networking controls
- **AWS Security Hub** — Automated security checks (IAM.1, EC2.18, EC2.19, EC2.21, RDS.5, RDS.11)
- **AWS Config Rules** — Managed rules (restricted-ssh, rds-multi-az-support, iam-policy-no-statements-with-admin-access)
- **AWS Well-Architected Framework** — Security (SEC03, SEC05), Reliability (REL02, REL06, REL09, REL10), Operations (OPS08)

Compliance tags appear in SARIF output and Markdown reports, making it easy to trace findings back to organizational policy.

---

## License

MIT
