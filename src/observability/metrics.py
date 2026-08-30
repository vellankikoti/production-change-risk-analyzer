from __future__ import annotations

import logging
import os
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class RiskMetrics:
    def __init__(self, namespace: str = "RiskAnalyzer", region: str | None = None) -> None:
        self.namespace = namespace
        region = region or os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-west-2"))
        self._cw = boto3.client("cloudwatch", region_name=region)

    def record_analysis(
        self,
        change_id: str,
        risk_level: str,
        risk_score: int,
        decision: str,
        environment: str,
        finding_count: int,
        duration_ms: float,
        ai_used: bool = False,
    ) -> None:
        dimensions = [
            {"Name": "Environment", "Value": environment},
        ]
        metric_data = [
            {
                "MetricName": "AnalysisCount",
                "Dimensions": dimensions,
                "Value": 1,
                "Unit": "Count",
            },
            {
                "MetricName": "RiskScore",
                "Dimensions": dimensions,
                "Value": risk_score,
                "Unit": "None",
            },
            {
                "MetricName": "FindingCount",
                "Dimensions": dimensions,
                "Value": finding_count,
                "Unit": "Count",
            },
            {
                "MetricName": "AnalysisDuration",
                "Dimensions": dimensions,
                "Value": duration_ms,
                "Unit": "Milliseconds",
            },
            {
                "MetricName": f"Decision_{decision}",
                "Dimensions": dimensions,
                "Value": 1,
                "Unit": "Count",
            },
            {
                "MetricName": f"RiskLevel_{risk_level}",
                "Dimensions": dimensions,
                "Value": 1,
                "Unit": "Count",
            },
        ]

        if ai_used:
            metric_data.append({
                "MetricName": "AIInvocationCount",
                "Dimensions": dimensions,
                "Value": 1,
                "Unit": "Count",
            })

        try:
            self._cw.put_metric_data(
                Namespace=self.namespace,
                MetricData=metric_data,
            )
            logger.info("Published %d metrics for %s", len(metric_data), change_id)
        except ClientError:
            logger.exception("Failed to publish metrics for %s", change_id)

    def record_rule_findings(self, findings: list[dict[str, Any]], environment: str) -> None:
        if not findings:
            return
        dimensions = [{"Name": "Environment", "Value": environment}]
        metric_data = []
        rule_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}

        for f in findings:
            rule_id = f.get("rule_id", "UNKNOWN")
            severity = f.get("severity", "UNKNOWN")
            rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        for rule_id, count in rule_counts.items():
            metric_data.append({
                "MetricName": "RuleTriggerCount",
                "Dimensions": dimensions + [{"Name": "RuleId", "Value": rule_id}],
                "Value": count,
                "Unit": "Count",
            })

        for severity, count in severity_counts.items():
            metric_data.append({
                "MetricName": "FindingsBySeverity",
                "Dimensions": dimensions + [{"Name": "Severity", "Value": severity}],
                "Value": count,
                "Unit": "Count",
            })

        try:
            for i in range(0, len(metric_data), 20):
                batch = metric_data[i:i + 20]
                self._cw.put_metric_data(Namespace=self.namespace, MetricData=batch)
            logger.info("Published rule finding metrics")
        except ClientError:
            logger.exception("Failed to publish rule finding metrics")
