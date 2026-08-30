from __future__ import annotations

import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def create_dashboard(
    dashboard_name: str = "RiskAnalyzer",
    namespace: str = "RiskAnalyzer",
    region: str | None = None,
) -> str:
    region = region or os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-west-2"))
    cw = boto3.client("cloudwatch", region_name=region)

    body = {
        "widgets": [
            {
                "type": "metric",
                "x": 0, "y": 0, "width": 6, "height": 6,
                "properties": {
                    "title": "Analyses Per Hour",
                    "metrics": [
                        [namespace, "AnalysisCount", "Environment", "production", {"stat": "Sum", "period": 3600}],
                        [namespace, "AnalysisCount", "Environment", "staging", {"stat": "Sum", "period": 3600}],
                        [namespace, "AnalysisCount", "Environment", "development", {"stat": "Sum", "period": 3600}],
                    ],
                    "view": "timeSeries",
                    "region": region,
                    "period": 3600,
                },
            },
            {
                "type": "metric",
                "x": 6, "y": 0, "width": 6, "height": 6,
                "properties": {
                    "title": "Decisions",
                    "metrics": [
                        [namespace, "Decision_BLOCK", "Environment", "production", {"stat": "Sum", "period": 3600, "color": "#d62728"}],
                        [namespace, "Decision_REVIEW", "Environment", "production", {"stat": "Sum", "period": 3600, "color": "#ff7f0e"}],
                        [namespace, "Decision_APPROVE", "Environment", "production", {"stat": "Sum", "period": 3600, "color": "#2ca02c"}],
                    ],
                    "view": "timeSeries",
                    "region": region,
                    "period": 3600,
                },
            },
            {
                "type": "metric",
                "x": 12, "y": 0, "width": 6, "height": 6,
                "properties": {
                    "title": "Risk Scores (Avg)",
                    "metrics": [
                        [namespace, "RiskScore", "Environment", "production", {"stat": "Average", "period": 3600}],
                        [namespace, "RiskScore", "Environment", "staging", {"stat": "Average", "period": 3600}],
                    ],
                    "view": "timeSeries",
                    "region": region,
                    "period": 3600,
                },
            },
            {
                "type": "metric",
                "x": 18, "y": 0, "width": 6, "height": 6,
                "properties": {
                    "title": "Analysis Duration (ms)",
                    "metrics": [
                        [namespace, "AnalysisDuration", "Environment", "production", {"stat": "Average", "period": 300}],
                        [namespace, "AnalysisDuration", "Environment", "production", {"stat": "p99", "period": 300}],
                    ],
                    "view": "timeSeries",
                    "region": region,
                    "period": 300,
                },
            },
            {
                "type": "metric",
                "x": 0, "y": 6, "width": 12, "height": 6,
                "properties": {
                    "title": "Risk Level Distribution",
                    "metrics": [
                        [namespace, "RiskLevel_CRITICAL", "Environment", "production", {"stat": "Sum", "period": 3600, "color": "#d62728"}],
                        [namespace, "RiskLevel_HIGH", "Environment", "production", {"stat": "Sum", "period": 3600, "color": "#ff7f0e"}],
                        [namespace, "RiskLevel_MEDIUM", "Environment", "production", {"stat": "Sum", "period": 3600, "color": "#ffbb78"}],
                        [namespace, "RiskLevel_LOW", "Environment", "production", {"stat": "Sum", "period": 3600, "color": "#2ca02c"}],
                    ],
                    "view": "bar",
                    "region": region,
                    "period": 3600,
                },
            },
            {
                "type": "metric",
                "x": 12, "y": 6, "width": 12, "height": 6,
                "properties": {
                    "title": "Findings by Severity",
                    "metrics": [
                        [namespace, "FindingsBySeverity", "Environment", "production", "Severity", "CRITICAL", {"stat": "Sum", "period": 3600, "color": "#d62728"}],
                        [namespace, "FindingsBySeverity", "Environment", "production", "Severity", "HIGH", {"stat": "Sum", "period": 3600, "color": "#ff7f0e"}],
                        [namespace, "FindingsBySeverity", "Environment", "production", "Severity", "MEDIUM", {"stat": "Sum", "period": 3600, "color": "#ffbb78"}],
                    ],
                    "view": "timeSeries",
                    "region": region,
                    "period": 3600,
                },
            },
            {
                "type": "metric",
                "x": 0, "y": 12, "width": 12, "height": 6,
                "properties": {
                    "title": "Top Triggered Rules",
                    "metrics": [
                        [namespace, "RuleTriggerCount", "Environment", "production", "RuleId", "SG-001", {"stat": "Sum", "period": 3600}],
                        [namespace, "RuleTriggerCount", "Environment", "production", "RuleId", "IAM-003", {"stat": "Sum", "period": 3600}],
                        [namespace, "RuleTriggerCount", "Environment", "production", "RuleId", "SG-004", {"stat": "Sum", "period": 3600}],
                        [namespace, "RuleTriggerCount", "Environment", "production", "RuleId", "AVAIL-003", {"stat": "Sum", "period": 3600}],
                    ],
                    "view": "timeSeries",
                    "region": region,
                    "period": 3600,
                },
            },
            {
                "type": "metric",
                "x": 12, "y": 12, "width": 12, "height": 6,
                "properties": {
                    "title": "AI Invocations & Finding Count",
                    "metrics": [
                        [namespace, "AIInvocationCount", "Environment", "production", {"stat": "Sum", "period": 3600}],
                        [namespace, "FindingCount", "Environment", "production", {"stat": "Average", "period": 3600}],
                    ],
                    "view": "timeSeries",
                    "region": region,
                    "period": 3600,
                },
            },
        ],
    }

    try:
        cw.put_dashboard(
            DashboardName=dashboard_name,
            DashboardBody=json.dumps(body),
        )
        console_url = f"https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#dashboards/dashboard/{dashboard_name}"
        logger.info("Dashboard created: %s", console_url)
        return console_url
    except ClientError:
        logger.exception("Failed to create dashboard")
        raise
