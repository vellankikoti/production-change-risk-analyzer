from __future__ import annotations

import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

from src.models.schemas import RiskReport

logger = logging.getLogger(__name__)


class RiskNotifier:
    def __init__(self, topic_arn: str | None = None, region: str | None = None) -> None:
        self.topic_arn = topic_arn or os.environ.get("RISK_ANALYZER_SNS_TOPIC", "")
        region = region or os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-west-2"))
        self._sns = boto3.client("sns", region_name=region)

    def notify(self, report: RiskReport) -> bool:
        if not self.topic_arn:
            logger.warning("No SNS topic ARN configured — skipping notification")
            return False

        risk_level = report.risk_level.value if hasattr(report.risk_level, "value") else report.risk_level
        if risk_level not in ("CRITICAL", "HIGH"):
            logger.debug("Skipping notification for %s risk level", risk_level)
            return False

        decision = report.decision.value if hasattr(report.decision, "value") else report.decision
        subject = f"[{risk_level}] Infrastructure Change Risk Alert — {decision}"

        findings_text = "\n".join(
            f"  - [{f.severity.value}] {f.finding}" for f in report.evidence.findings
        )

        message = f"""Infrastructure Change Risk Report
===================================
Change ID:   {report.change_id}
Environment: {report.evidence.environment}
Risk Level:  {risk_level}
Risk Score:  {report.risk_score}/100
Decision:    {decision}
Timestamp:   {report.timestamp}

Findings:
{findings_text}

AI Analysis:
{report.ai_analysis.explanation or 'N/A'}

Remediation:
{report.ai_analysis.remediation or 'See individual findings for remediation steps.'}
"""

        try:
            self._sns.publish(
                TopicArn=self.topic_arn,
                Subject=subject[:100],
                Message=message,
                MessageAttributes={
                    "risk_level": {"DataType": "String", "StringValue": risk_level},
                    "decision": {"DataType": "String", "StringValue": decision},
                    "change_id": {"DataType": "String", "StringValue": report.change_id},
                },
            )
            logger.info("Sent notification for %s to %s", report.change_id, self.topic_arn)
            return True
        except ClientError:
            logger.exception("Failed to send SNS notification")
            return False
