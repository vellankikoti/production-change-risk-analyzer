from __future__ import annotations

import json
import logging
import os
from decimal import Decimal
from typing import Any

import boto3
from botocore.exceptions import ClientError

from src.models.schemas import RiskReport

logger = logging.getLogger(__name__)


def _convert_floats(obj: Any) -> Any:
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _convert_floats(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_convert_floats(v) for v in obj]
    return obj


def _convert_decimals(obj: Any) -> Any:
    if isinstance(obj, Decimal):
        if obj % 1 == 0:
            return int(obj)
        return float(obj)
    if isinstance(obj, dict):
        return {k: _convert_decimals(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_convert_decimals(v) for v in obj]
    return obj


class RiskReportStore:
    def __init__(self, table_name: str | None = None, region: str | None = None) -> None:
        self.table_name = table_name or os.environ.get("RISK_ANALYZER_TABLE", "risk-analyzer-reports")
        region = region or os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-west-2"))
        self._dynamodb = boto3.resource("dynamodb", region_name=region)
        self._table = self._dynamodb.Table(self.table_name)

    def save_report(self, report: RiskReport) -> None:
        item = _convert_floats(report.to_dict())
        item["pk"] = report.change_id
        item["sk"] = report.timestamp
        item["risk_level"] = report.risk_level.value if hasattr(report.risk_level, "value") else report.risk_level
        item["decision"] = report.decision.value if hasattr(report.decision, "value") else report.decision
        item["environment"] = report.evidence.environment

        self._table.put_item(Item=item)
        logger.info("Saved report %s to DynamoDB", report.change_id)

    def get_report(self, change_id: str) -> RiskReport | None:
        try:
            response = self._table.query(
                KeyConditionExpression="pk = :pk",
                ExpressionAttributeValues={":pk": change_id},
                ScanIndexForward=False,
                Limit=1,
            )
            items = response.get("Items", [])
            if not items:
                return None
            item = _convert_decimals(items[0])
            return RiskReport.from_dict(item)
        except ClientError:
            logger.exception("Failed to get report %s", change_id)
            return None

    def list_reports(
        self,
        environment: str | None = None,
        risk_level: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        try:
            if risk_level:
                response = self._table.query(
                    IndexName="risk-level-index",
                    KeyConditionExpression="risk_level = :rl",
                    ExpressionAttributeValues={":rl": risk_level},
                    ScanIndexForward=False,
                    Limit=limit,
                )
            else:
                response = self._table.scan(Limit=limit)

            items = [_convert_decimals(i) for i in response.get("Items", [])]
            if environment:
                items = [i for i in items if i.get("environment") == environment]
            return items
        except ClientError:
            logger.exception("Failed to list reports")
            return []

    def get_blocked_reports(self, limit: int = 50) -> list[dict[str, Any]]:
        try:
            response = self._table.scan(
                FilterExpression="decision = :d",
                ExpressionAttributeValues={":d": "BLOCK"},
                Limit=limit,
            )
            return [_convert_decimals(i) for i in response.get("Items", [])]
        except ClientError:
            logger.exception("Failed to get blocked reports")
            return []
