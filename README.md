# Production Change Risk Analyzer

**Evidence-based infrastructure change risk analysis for AWS CloudFormation.** 27 deterministic rules detect security, availability, encryption, logging, and data protection risks. AI explains the findings — it never decides BLOCK or APPROVE.

[![CI](https://github.com/vellankikoti/production-change-risk-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/vellankikoti/production-change-risk-analyzer/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

---

## Why This Exists

Production deployments fail because teams deploy CloudFormation changes without understanding the risk surface. Security groups open to the world, IAM policies granting admin access, Multi-AZ silently disabled, encryption missing, logging deleted — these patterns are detectable before deployment, not after an incident.

This tool catches them with deterministic rules (no AI guesswork), maps findings to compliance frameworks (CIS, SecurityHub, Well-Architected), and integrates into your CI/CD pipeline to block dangerous changes before they reach production.

**What makes this different:**
- **Deterministic decisions.** BLOCK/REVIEW/APPROVE is based on rule severity thresholds — never AI. The AI only explains what the rules found.
- **FACT vs INFERENCE separation.** AI output explicitly labels what is directly observable (FACT) vs what is inferred (INFERENCE). No hallucinated risks.
- **Compliance-mapped.** Every rule traces to CIS AWS Foundations Benchmark, AWS Security Hub controls, AWS Config rules, and Well-Architected Framework pillars.
- **Works without AWS.** Run `--no-ai` for fully local, deterministic analysis — no credentials needed.

---

## Architecture

```
┌─────────────────────┐     ┌──────────────────────┐     ┌─────────────────────┐
│  CloudFormation      │     │  27 Deterministic     │     │  Evidence Package    │
│  Template (YAML/JSON)│────▶│  Rules Engine         │────▶│  (findings + context)│
│  Before + After      │     │  7 categories         │     │                     │
└─────────────────────┘     └──────────────────────┘     └────────┬────────────┘
                                                                   │
                              ┌─────────────────────┐              │
                              │  Risk Score          │◀─────── Deterministic
                              │  (threshold-based)   │         Thresholds
                              │  BLOCK/REVIEW/APPROVE│              │
                              └─────────────────────┘              │
                                                                   ▼
                              ┌─────────────────────┐     ┌─────────────────────┐
                              │  Risk Report         │◀────│  AI Explanation      │
                              │  (5 output formats)  │     │  (FACT vs INFERENCE) │
                              └─────────────────────┘     │  amazon.nova-lite    │
                                                          └─────────────────────┘
```

**The AI layer is advisory only.** If Bedrock is unavailable, throttled, or disabled (`--no-ai`), you still get a complete risk report with all findings, scores, and decisions. AI adds explanation, blast radius assessment, operational impact, and remediation — but never changes the verdict.

---

## Quick Start

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) package manager (recommended) or pip

For AI analysis (optional):
- AWS CLI configured with credentials
- Amazon Bedrock access to `amazon.nova-lite-v1:0`

### Step 1: Install

```bash
git clone https://github.com/vellankikoti/production-change-risk-analyzer.git
cd production-change-risk-analyzer

# Using uv (recommended)
uv venv && source .venv/bin/activate
uv pip install -r requirements.txt

# Or using pip
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Step 2: Analyze a template

```bash
# Analyze a new stack (no AI — works without AWS credentials)
python cli.py analyze --after tests/fixtures/templates/dangerous_changes.yaml --no-ai

# Compare before/after changes in production
python cli.py analyze \
  --before tests/fixtures/templates/secure_baseline.yaml \
  --after tests/fixtures/templates/dangerous_changes.yaml \
  --environment production

# With AI explanation (requires AWS credentials + Bedrock access)
python cli.py analyze \
  --before tests/fixtures/templates/secure_baseline.yaml \
  --after tests/fixtures/templates/dangerous_changes.yaml \
  --environment production
```

### Step 3: Verify the rules engine

```bash
# Run the evaluation suite (7 scenarios, deterministic)
python cli.py eval

# Expected output: 7/7 PASS, 100% accuracy across all metrics
```

### Step 4: Run tests

```bash
pytest tests/ -v
# Expected: 112 tests passing
```

---

## Output Formats

| Format | Flag | Use Case |
|:-------|:-----|:---------|
| Rich terminal | `--format rich` (default) | Interactive review |
| JSON | `--format json` | Programmatic consumption, API integration |
| SARIF v2.1.0 | `--format sarif` | GitHub Security tab, VS Code SARIF Viewer |
| Markdown | `--format markdown` | PR comments, documentation |
| JUnit XML | `--format junit` | CI test reporting (Jenkins, GitHub Actions) |

```bash
# SARIF for GitHub Security tab
python cli.py analyze --after template.yaml --format sarif --output-file results.sarif

# Markdown for PR comment
python cli.py analyze --after template.yaml --format markdown --output-file report.md

# JUnit XML for CI
python cli.py analyze --after template.yaml --format junit --output-file results.xml

# JSON piped to jq
python cli.py analyze --after template.yaml --format json | jq '.decision'
```

---

## Rules Reference (27 Rules, 7 Categories)

Every rule maps to compliance frameworks: **CIS AWS Foundations Benchmark**, **AWS Security Hub**, **AWS Config Rules**, and **AWS Well-Architected Framework**.

### IAM (5 rules)

| Rule | What It Detects | Severity | Key Compliance |
|:-----|:---------------|:---------|:---------------|
| IAM-001 | Wildcard actions (`Action: "*"`) in IAM policies | CRITICAL | CIS 1.16, SecurityHub IAM.1 |
| IAM-002 | Wildcard resources (`Resource: "*"`) | HIGH | CIS 1.16, SecurityHub IAM.1, WA SEC03-BP07 |
| IAM-003 | Full admin: `Action: "*"` + `Resource: "*"` combined | CRITICAL | CIS 1.16, SecurityHub IAM.1, AWS Config iam-policy-no-statements-with-admin-access |
| IAM-004 | Privilege escalation: `iam:PassRole`, `sts:AssumeRole *` | HIGH | CIS 1.16, WA SEC03-BP06 |
| IAM-005 | Broad data access: `s3:*`, `dynamodb:*`, etc. | MEDIUM | CIS 1.16, WA SEC03-BP07 |

### Security Groups (4 rules)

| Rule | What It Detects | Severity | Key Compliance |
|:-----|:---------------|:---------|:---------------|
| SG-001 | 0.0.0.0/0 to sensitive ports (SSH 22, RDP 3389, DBs) | CRITICAL | CIS 5.2/5.3, SecurityHub EC2.19 |
| SG-002 | Unrestricted ingress 0.0.0.0/0 on any port | MEDIUM | CIS 5.2, SecurityHub EC2.18 |
| SG-003 | Port ranges wider than 100 ports | MEDIUM | WA SEC05-BP02 |
| SG-004 | All traffic (protocol `-1`) from any source | CRITICAL | CIS 5.2/5.3, SecurityHub EC2.19 |

### Network (4 rules)

| Rule | What It Detects | Severity | Key Compliance |
|:-----|:---------------|:---------|:---------------|
| NET-001 | Subnet associated with IGW route table | HIGH | CIS 5.1, WA SEC05-BP01 |
| NET-002 | NAT Gateway deletion (breaks private subnet internet) | HIGH | WA REL02-BP01 |
| NET-003 | NACL allowing all inbound from 0.0.0.0/0 | MEDIUM | CIS 5.1, SecurityHub EC2.21 |
| NET-004 | Default route (0.0.0.0/0) to Internet Gateway | HIGH | CIS 5.1, WA SEC05-BP01 |

### Availability (5 rules)

| Rule | What It Detects | Severity | Key Compliance |
|:-----|:---------------|:---------|:---------------|
| AVAIL-001 | ASG desired capacity reduction | MEDIUM | WA REL06-BP01 |
| AVAIL-002 | ASG min capacity below 2 (single point of failure) | HIGH | WA REL10-BP01 |
| AVAIL-003 | Multi-AZ disabled on RDS | CRITICAL | SecurityHub RDS.5, WA REL10-BP01 |
| AVAIL-004 | Deletion of critical resources (RDS, DynamoDB, ECS, EKS) | CRITICAL | WA OPS08-BP01 |
| AVAIL-005 | Backup retention reduced to 0 days | HIGH | SecurityHub RDS.11, WA REL09-BP01 |

### Encryption (3 rules)

| Rule | What It Detects | Severity | Key Compliance |
|:-----|:---------------|:---------|:---------------|
| ENC-001 | S3 bucket without server-side encryption | HIGH | CIS 2.1.1, SecurityHub S3.4, WA SEC08-BP02 |
| ENC-002 | RDS instance without storage encryption | CRITICAL | CIS 2.3.1, SecurityHub RDS.3, WA SEC08-BP02 |
| ENC-003 | EBS volume without encryption | HIGH | CIS 2.2.1, SecurityHub EC2.3, WA SEC08-BP02 |

### Logging & Monitoring (3 rules)

| Rule | What It Detects | Severity | Key Compliance |
|:-----|:---------------|:---------|:---------------|
| LOG-001 | S3 bucket without access logging | MEDIUM | CIS 3.6, SecurityHub S3.9, WA SEC04-BP02 |
| LOG-002 | CloudTrail trail deletion | CRITICAL | CIS 3.1, SecurityHub CloudTrail.1, WA SEC04-BP01 |
| LOG-003 | CloudTrail logging disabled (`IsLogging: false`) | CRITICAL | CIS 3.1, SecurityHub CloudTrail.1, WA SEC04-BP01 |

### Data Protection (3 rules)

| Rule | What It Detects | Severity | Key Compliance |
|:-----|:---------------|:---------|:---------------|
| S3-001 | S3 bucket without public access block | CRITICAL | CIS 2.1.5, SecurityHub S3.1/S3.2/S3.3, WA SEC08-BP04 |
| RDS-001 | RDS instance with `PubliclyAccessible: true` | CRITICAL | CIS 2.3.2, SecurityHub RDS.2, WA SEC05-BP01 |
| DEL-001 | Critical resources without deletion protection | HIGH | SecurityHub RDS.8, WA REL09-BP01 |

---

## Risk Scoring

Scoring is fully deterministic — no AI involvement in the decision.

### How scores are calculated

1. Each finding has a severity: CRITICAL, HIGH, MEDIUM, or LOW
2. The **highest severity** across all findings determines the risk level
3. The count of findings at that severity determines the exact score:

| Highest Severity | Base Score | Per-Finding Bonus | Score Range | Decision |
|:----------------|:-----------|:-----------------|:------------|:---------|
| CRITICAL | 80 | +5 per CRITICAL finding | 80–100 | **BLOCK** |
| HIGH | 60 | +5 per HIGH finding | 60–79 | **REVIEW** |
| MEDIUM | 40 | +5 per MEDIUM finding | 40–59 | **REVIEW** |
| LOW | 10 | +5 per LOW finding | 10–39 | **APPROVE** |
| No findings | 5 | — | 5 | **APPROVE** |

### Exit codes

| Decision | Exit Code | CI Behavior |
|:---------|:----------|:------------|
| APPROVE | 0 | Pipeline continues |
| REVIEW | 1 | Pipeline fails (configurable) |
| BLOCK | 1 | Pipeline fails |

---

## AI Analysis: FACT vs INFERENCE

When AI is enabled (default), the analyzer sends the evidence package to Amazon Bedrock for explanation. The AI output is strictly structured:

- **FACTS** — directly observable from the evidence (e.g., "Port 5432 is open to CIDR 0.0.0.0/0")
- **INFERENCES** — conclusions drawn from facts (e.g., "The PostgreSQL database could be reachable from the public internet")

The AI also provides:
- **Blast radius** — what systems and data are affected
- **Operational impact** — what breaks or degrades
- **Remediation steps** — specific fixes for each finding

```
Model:           amazon.nova-lite-v1:0 (configurable)
Retry:           3 attempts with exponential backoff on throttling
Token limit:     Evidence truncated to 15K chars if oversized
Graceful fallback: If AI fails, deterministic report still completes
```

---

## Configuration

Create `risk-analyzer.yaml` in your project root to customize behavior per repository and environment.

```yaml
# Scoring thresholds (adjust sensitivity)
thresholds:
  critical_min: 80
  high_min: 60
  medium_min: 40

# AI configuration
ai:
  enabled: true
  model_id: amazon.nova-lite-v1:0
  max_tokens: 2048

# Disable specific rules globally
disabled_rules:
  - SG-003    # Wide port ranges acceptable in this project

# Per-environment overrides
environments:
  production:
    block_on_high: true       # BLOCK on HIGH findings (not just CRITICAL)
    thresholds:
      critical_min: 70        # Stricter scoring in production
      high_min: 50
  development:
    disabled_rules:
      - SG-002                # Allow unrestricted ingress in dev
    severity_overrides:
      IAM-002: MEDIUM         # Downgrade wildcard resources in dev

# Suppressions (accepted risks with audit trail)
suppressions:
  - rule_id: SG-001
    resource_pattern: "DevSecurityGroup"
    reason: "Accepted risk — approved in SEC-1234"
    expires: "2025-12-31T00:00:00Z"    # Auto-reinstates after expiry

  - rule_id: ENC-001
    resource_pattern: "PublicAssetsBucket"
    reason: "Public static assets — encryption not required"
```

See [`risk-analyzer.yaml`](risk-analyzer.yaml) for the full annotated default configuration.

---

## CI/CD Integration

### GitHub Actions (recommended)

Copy `.github/workflows/risk-analyze.yml` to your repository. On every PR that changes CloudFormation files:

1. Detects changed `.yaml`/`.json` files matching CloudFormation patterns
2. Runs deterministic risk analysis (fast, no AI dependency)
3. Uploads SARIF to GitHub Security tab (findings appear inline on the PR)
4. Posts a Markdown risk summary as a PR comment
5. Fails the check if any file triggers BLOCK

**Setup:**
1. Copy the workflow file to your repo's `.github/workflows/`
2. Set `AWS_REGION` as a repository variable (optional — defaults to `us-west-2`)
3. For AI analysis, add AWS credentials as repository secrets (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)

### Any CI System (Jenkins, GitLab, CircleCI, etc.)

```bash
# Basic gate — exits 1 on BLOCK/REVIEW, 0 on APPROVE
python cli.py analyze \
  --before baseline.yaml \
  --after proposed.yaml \
  --environment production \
  --no-ai

# SARIF output for security scanning integration
python cli.py analyze \
  --after proposed.yaml \
  --no-ai \
  --format sarif \
  --output-file results.sarif

# JSON for custom processing
python cli.py analyze \
  --after proposed.yaml \
  --no-ai \
  --format json | jq '{decision, risk_score, risk_level}'
```

### AWS CodeBuild

See [`ci/buildspec.yaml`](ci/buildspec.yaml) for a ready-to-use buildspec and [`ci/codebuild-project.yaml`](ci/codebuild-project.yaml) for the CloudFormation project definition.

---

## AWS Integrations (All Optional)

The core analyzer works entirely offline with `--no-ai`. AWS integrations add persistence, alerting, and observability.

### DynamoDB — Report Storage

Store every analysis for audit trail and historical trending.

```bash
python cli.py analyze --after template.yaml --save

# Retrieve by change ID
python cli.py report CHG-A1B2C3D4

# List recent reports filtered by risk level
python cli.py list --risk-level CRITICAL --limit 10

# View trends: risk distribution, block rate, environment breakdown
python cli.py trending
```

### S3 — Evidence Archival

Archive the full evidence package (findings, resource changes, templates) for post-incident analysis.

```bash
python cli.py analyze --before current.yaml --after proposed.yaml --save-evidence
```

### SNS — Notifications

Alert on-call teams when HIGH or CRITICAL changes are detected.

```bash
python cli.py analyze --after template.yaml --notify

# Subscribe an email
python cli.py subscribe oncall@company.com
```

### CloudWatch — Metrics & Dashboard

Real-time operational visibility with 8 pre-built widgets.

```bash
python cli.py dashboard
```

Published metrics: `AnalysisCount`, `RiskScore`, `FindingCount`, `AnalysisDuration`, `Decision_BLOCK/REVIEW/APPROVE`, `RiskLevel_CRITICAL/HIGH/MEDIUM/LOW`, `RuleTriggerCount`, `FindingsBySeverity`.

### Infrastructure Setup

```bash
# Option 1: CloudFormation (if your account permits)
aws cloudformation deploy \
  --template-file infra/risk-analyzer-infra.yaml \
  --stack-name risk-analyzer \
  --parameter-overrides Environment=prod \
  --capabilities CAPABILITY_NAMED_IAM

# Option 2: AWS CLI (manual)
source setup-env.sh
```

---

## Web Dashboard

```bash
python web_server.py
# Opens at http://localhost:8501
```

- Upload templates for on-demand analysis
- View historical reports with risk level distribution
- Quick-test with built-in fixture templates
- Full report view with AI analysis, facts, and inferences

---

## Evaluation Framework

7 built-in scenarios validate rules fire correctly and risk levels match expectations.

```bash
# Deterministic evaluation (no AWS credentials needed)
python cli.py eval

# With AI quality scoring (8 dimensions)
python cli.py eval --ai

# JSON for CI integration
python cli.py eval --json-output
```

**Evaluation metrics:**
- Risk level accuracy — expected vs actual (CRITICAL/HIGH/MEDIUM/LOW)
- Decision accuracy — expected vs actual (BLOCK/REVIEW/APPROVE)
- Rule detection accuracy — expected rule IDs fire
- AI quality (8 checks): explanation presence, facts, inferences, grounding, hallucination detection, remediation, blast radius, structured output

**Scenarios:**
| ID | Scenario | Expected |
|:---|:---------|:---------|
| EVAL-001 | Public database exposure (SG opens PostgreSQL to 0.0.0.0/0) | CRITICAL / BLOCK |
| EVAL-002 | IAM admin permissions (Action: *, Resource: *) | CRITICAL / BLOCK |
| EVAL-003 | Production redundancy reduction (ASG, Multi-AZ, backups) | CRITICAL / BLOCK |
| EVAL-004 | Minor metadata/tag change (no security impact) | LOW / APPROVE |
| EVAL-005 | New stack with public ALB and broad S3 access | HIGH / REVIEW |
| EVAL-006 | No changes (identical before/after) | LOW / APPROVE |
| EVAL-007 | Encryption, logging, and data protection violations | CRITICAL / BLOCK |

---

## Writing Custom Rules

Extend the analyzer with organization-specific checks.

### Step 1: Create a rule

```python
# src/rules/my_rules.py
from src.models.schemas import ChangeType, ResourceChange, RuleFinding, Severity
from src.rules.base import Rule

class NoPublicLoadBalancer(Rule):
    rule_id = "ORG-001"
    name = "No public ALBs in private subnets"
    description = "Detects ALBs with Scheme: internet-facing in private VPCs"
    severity = Severity.HIGH
    compliance = ["Internal-Policy-NET-01", "Well-Architected: SEC05-BP01"]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in (
            "AWS::ElasticLoadBalancingV2::LoadBalancer",
        )

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        props = change.after or {}
        if props.get("Scheme") == "internet-facing":
            return [RuleFinding(
                rule_id=self.rule_id,
                severity=self.severity,
                resource=change.resource_id,
                finding="ALB is internet-facing — verify this is intentional",
                evidence={"scheme": props.get("Scheme")},
                remediation="Set Scheme to 'internal' if this ALB serves only private traffic",
                compliance=self.compliance,
            )]
        return []
```

### Step 2: Register it

```python
# In src/analyzer/orchestrator.py, add to _build_rule_engine():
from src.rules.my_rules import NoPublicLoadBalancer

def _build_rule_engine() -> RuleEngine:
    engine = RuleEngine()
    # ... existing rules ...
    engine.register(NoPublicLoadBalancer())
    return engine
```

### Step 3: Add an eval scenario

```json
{
  "id": "EVAL-ORG-001",
  "description": "Internet-facing ALB detected",
  "before": null,
  "after": "tests/fixtures/templates/public_alb.yaml",
  "environment": "production",
  "expected_risk_level": "HIGH",
  "expected_decision": "REVIEW",
  "expected_rule_ids": ["ORG-001"]
}
```

---

## Compliance Framework Reference

| Framework | Coverage | Rules |
|:----------|:---------|:------|
| **CIS AWS Foundations Benchmark** | 1.16 (IAM), 2.x (Encryption/Data), 3.x (Logging), 5.x (Networking) | IAM-001–005, SG-001–004, NET-001–004, ENC-001–003, LOG-001–003, S3-001, RDS-001 |
| **AWS Security Hub** | IAM.1, EC2.3/18/19/21, RDS.2/3/5/8/11, S3.1–4/9, CloudTrail.1 | All 27 rules |
| **AWS Config Rules** | iam-policy-no-statements-with-admin-access, restricted-ssh, restricted-common-ports, rds-multi-az-support, rds-storage-encrypted, s3-bucket-server-side-encryption-enabled, cloudtrail-enabled, etc. | All 27 rules |
| **AWS Well-Architected** | SEC03, SEC04, SEC05, SEC08, REL02, REL06, REL09, REL10, OPS08 | All 27 rules |

Compliance tags appear in SARIF output and Markdown reports — trace any finding directly to your organization's control framework.

---

## Project Structure

```
production-change-risk-analyzer/
├── cli.py                         # CLI: analyze, report, list, eval, trending, dashboard, subscribe
├── web_server.py                  # FastAPI web dashboard launcher
├── risk-analyzer.yaml             # Default configuration (annotated)
├── requirements.txt
├── src/
│   ├── analyzer/
│   │   └── orchestrator.py        # Pipeline: parse → rules → evidence → AI → decision
│   ├── ai/
│   │   └── bedrock_analyzer.py    # Bedrock integration (retry, token protection, FACT/INFERENCE)
│   ├── config.py                  # YAML config loader (env overrides, suppressions)
│   ├── models/
│   │   └── schemas.py             # Data models (ResourceChange, RuleFinding, RiskReport, etc.)
│   ├── output/
│   │   ├── sarif.py               # SARIF v2.1.0 (GitHub Security tab)
│   │   ├── markdown.py            # Markdown (PR comments)
│   │   └── junit.py               # JUnit XML (CI reporting)
│   ├── parser/
│   │   └── cloudformation.py      # CFn YAML/JSON parser with intrinsic function support
│   ├── rules/
│   │   ├── base.py                # Rule ABC and RuleEngine
│   │   ├── iam.py                 # IAM-001 – IAM-005
│   │   ├── security_group.py      # SG-001 – SG-004
│   │   ├── network.py             # NET-001 – NET-004
│   │   ├── availability.py        # AVAIL-001 – AVAIL-005
│   │   ├── encryption.py          # ENC-001 – ENC-003
│   │   ├── logging.py             # LOG-001 – LOG-003
│   │   └── data.py                # S3-001, RDS-001, DEL-001
│   ├── evaluation/
│   │   └── runner.py              # 7 scenarios, 8 AI quality dimensions
│   ├── notifications/
│   │   └── sns.py                 # SNS alerts for HIGH/CRITICAL
│   ├── observability/
│   │   ├── metrics.py             # CloudWatch custom metrics (8 metric types)
│   │   └── dashboard.py           # CloudWatch dashboard (8 widgets)
│   ├── storage/
│   │   ├── dynamodb.py            # Report storage (PK=change_id, GSI on risk_level)
│   │   └── s3.py                  # Evidence archival with versioning
│   └── web/
│       ├── app.py                 # FastAPI application
│       └── templates/             # Jinja2 (dashboard, analyze, report)
├── tests/                         # 112 tests
│   ├── test_rules/                # Unit tests for all 27 rules
│   ├── test_analyzer/             # Integration tests for orchestrator
│   └── test_output/               # SARIF, Markdown output tests
├── eval/
│   └── scenarios.json             # 7 evaluation scenarios
├── ci/
│   ├── buildspec.yaml             # AWS CodeBuild buildspec
│   ├── codebuild-project.yaml     # CodeBuild project template
│   └── run-local.sh               # Local CI runner
├── infra/
│   └── risk-analyzer-infra.yaml   # CloudFormation: DynamoDB, S3, SNS, CloudWatch
└── .github/workflows/
    ├── risk-analyze.yml           # PR risk analysis (SARIF + comment + gate)
    └── ci.yml                     # Tests + evaluation
```

---

## Running Without AWS (Local Development)

The analyzer works fully offline for deterministic analysis:

```bash
# No AWS credentials needed — rules-only mode
python cli.py analyze --after your-template.yaml --no-ai

# Run tests (mocked AWS, no credentials needed)
pytest tests/ -v

# Run evaluation (deterministic, no AWS)
python cli.py eval
```

Only these features require AWS credentials:
- AI analysis (Bedrock) — disable with `--no-ai`
- Report storage (`--save`) — requires DynamoDB
- Evidence archival (`--save-evidence`) — requires S3
- Notifications (`--notify`) — requires SNS
- Metrics/dashboard — requires CloudWatch

---

## Tests

```bash
# All tests (112 tests, ~0.5s)
pytest tests/ -v

# By category
pytest tests/test_rules/ -v        # Rule unit tests
pytest tests/test_analyzer/ -v     # Orchestrator integration
pytest tests/test_output/ -v       # Output format tests

# Evaluation (7 scenarios)
python cli.py eval
python cli.py eval --json-output   # Machine-readable
```

---

## License

MIT
