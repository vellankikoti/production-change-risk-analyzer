# Production Change Risk Analyzer

AI-assisted, evidence-based infrastructure change risk analysis. Detects risky CloudFormation changes before deployment using deterministic rules and AI reasoning.

## Architecture

```
Infrastructure Change → CloudFormation Parser → Deterministic Rules Engine → Evidence Package → AI Analysis → Risk Report
```

- **Deterministic rules** detect known patterns (public security groups, wildcard IAM, capacity reductions)
- **AI layer** explains risks, estimates blast radius, and recommends remediation
- **Policy engine** makes final APPROVE/REVIEW/BLOCK decisions based on deterministic thresholds

## Setup

```bash
cd production-change-risk-analyzer
uv venv && source .venv/bin/activate
uv pip install -r requirements.txt
```

## Usage

```bash
# Analyze a change (before → after)
python cli.py analyze --before templates/baseline.yaml --after templates/proposed.yaml --environment production

# Analyze a new stack
python cli.py analyze --after templates/new_stack.yaml

# Skip AI analysis (deterministic rules only)
python cli.py analyze --before templates/baseline.yaml --after templates/proposed.yaml --no-ai

# Output JSON
python cli.py analyze --after templates/proposed.yaml --json-output

# Save to DynamoDB and notify
python cli.py analyze --before templates/baseline.yaml --after templates/proposed.yaml --save --notify
```

## Run Tests

```bash
pytest tests/ -v
```

## Deploy Infrastructure

```bash
aws cloudformation deploy \
  --template-file infra/risk-analyzer-infra.yaml \
  --stack-name risk-analyzer-dev \
  --parameter-overrides Environment=dev \
  --capabilities CAPABILITY_NAMED_IAM
```

## Rules

| Rule ID   | Category     | Description                          | Severity |
|-----------|-------------|--------------------------------------|----------|
| IAM-001   | IAM         | Wildcard actions                     | CRITICAL |
| IAM-002   | IAM         | Wildcard resources                   | HIGH     |
| IAM-003   | IAM         | Combined wildcard (full admin)       | CRITICAL |
| IAM-004   | IAM         | Privilege escalation patterns        | HIGH     |
| IAM-005   | IAM         | Broad data access (s3:*, dynamodb:*) | MEDIUM   |
| SG-001    | Security    | Public access to sensitive ports     | CRITICAL |
| SG-002    | Security    | Unrestricted ingress                 | MEDIUM   |
| SG-003    | Security    | Wide port ranges                     | MEDIUM   |
| SG-004    | Security    | All traffic from any source          | CRITICAL |
| NET-001   | Network     | Public subnet for private resources  | HIGH     |
| NET-002   | Network     | NAT Gateway removal                  | HIGH     |
| NET-003   | Network     | Overly permissive NACL               | MEDIUM   |
| NET-004   | Network     | IGW route for private subnets        | HIGH     |
| AVAIL-001 | Availability| Reduced desired capacity             | MEDIUM+  |
| AVAIL-002 | Availability| Min capacity below 2                 | HIGH     |
| AVAIL-003 | Availability| Multi-AZ disabled                    | CRITICAL |
| AVAIL-004 | Availability| Critical resource deletion           | CRITICAL |
| AVAIL-005 | Availability| Backups disabled                     | HIGH     |

## Decision Thresholds

| Findings        | Decision | Score Range |
|----------------|----------|-------------|
| Any CRITICAL   | BLOCK    | 80-100      |
| Any HIGH       | REVIEW   | 60-79       |
| Only MEDIUM    | REVIEW   | 40-59       |
| Only LOW/INFO  | APPROVE  | 0-39        |
