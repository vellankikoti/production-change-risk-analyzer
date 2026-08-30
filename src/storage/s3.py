from __future__ import annotations

import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

from src.models.schemas import EvidencePackage

logger = logging.getLogger(__name__)


class EvidenceStore:
    def __init__(self, bucket_name: str | None = None, region: str | None = None) -> None:
        self.bucket_name = bucket_name or os.environ.get("RISK_ANALYZER_BUCKET", "risk-analyzer-evidence")
        region = region or os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-west-2"))
        self._s3 = boto3.client("s3", region_name=region)

    def save_evidence(self, evidence: EvidencePackage) -> str:
        key = f"evidence/{evidence.change_id}/{evidence.timestamp}.json"
        self._s3.put_object(
            Bucket=self.bucket_name,
            Key=key,
            Body=json.dumps(evidence.to_dict(), indent=2, default=str),
            ContentType="application/json",
        )
        logger.info("Saved evidence to s3://%s/%s", self.bucket_name, key)
        return key

    def save_templates(self, change_id: str, before: str | None, after: str) -> None:
        if before:
            self._s3.put_object(
                Bucket=self.bucket_name,
                Key=f"templates/{change_id}/before.yaml",
                Body=before,
                ContentType="text/yaml",
            )
        self._s3.put_object(
            Bucket=self.bucket_name,
            Key=f"templates/{change_id}/after.yaml",
            Body=after,
            ContentType="text/yaml",
        )
        logger.info("Saved templates for %s to S3", change_id)

    def get_evidence(self, change_id: str) -> EvidencePackage | None:
        try:
            prefix = f"evidence/{change_id}/"
            response = self._s3.list_objects_v2(Bucket=self.bucket_name, Prefix=prefix, MaxKeys=1)
            contents = response.get("Contents", [])
            if not contents:
                return None
            key = contents[0]["Key"]
            obj = self._s3.get_object(Bucket=self.bucket_name, Key=key)
            data = json.loads(obj["Body"].read())
            return EvidencePackage.from_dict(data)
        except ClientError:
            logger.exception("Failed to get evidence for %s", change_id)
            return None
