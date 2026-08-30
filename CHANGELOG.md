# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-30

### Added

- **Deterministic rules engine** with 27 rules across 7 categories: IAM, Security Groups, Network, Availability, Encryption, Logging, Data Protection
- **Explainable scoring** with category-based breakdown showing per-category score contributions
- **Blast radius analysis** via dependency graph built from CloudFormation Ref, Fn::GetAtt, DependsOn, and Fn::Sub
- **Rollback risk assessment** per resource based on change type and replacement-triggering properties
- **AI reasoning layer** using Amazon Bedrock (Nova Lite) with FACT/INFERENCE separation
- **Terraform plan support** (`terraform show -json` output parsing with type mapping)
- **AWS CloudFormation ChangeSet support** with replacement detection
- **Policy-as-Code engine** with 12 condition types, change freezes, and environment overrides
- **GitHub Action** for CI/CD integration with configurable gating thresholds
- **Configuration system** via `risk-analyzer.yaml` with rule disable, severity overrides, suppressions with expiry, and per-environment thresholds
- **Multiple output formats**: Rich terminal, JSON, SARIF v2.1.0, Markdown, JUnit XML
- **Compliance mapping** to CIS AWS Foundations, SecurityHub, AWS Config Rules, and Well-Architected Framework
- **FastAPI web dashboard** for browser-based analysis
- **CloudWatch observability** with metrics and dashboards
- **DynamoDB storage** for historical report persistence
- **SNS notifications** for risk alerts
- **Evaluation framework** with 7 scenarios and AI quality scoring
- **pip-installable package** (`change-risk-analyzer`) with `risk-analyzer` CLI entry point
- 5 example CloudFormation templates with a test runner script
- 289 unit and integration tests
