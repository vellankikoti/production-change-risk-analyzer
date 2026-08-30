from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError

from src.models.schemas import AIAnalysis, EvidencePackage

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a production infrastructure risk analyst. Your job is to analyze infrastructure changes and provide structured risk assessments.

You will receive an evidence package containing:
- Infrastructure changes (what resources are being created, modified, or deleted)
- Deterministic rule findings (security, IAM, network, and availability issues detected by automated rules)
- Environment context

Your analysis must:
1. Explain the risk in clear engineering language
2. Assess the potential blast radius (what systems, users, or services could be affected)
3. Describe the operational impact (what could go wrong in production)
4. Recommend specific remediation steps
5. State your confidence level (HIGH, MEDIUM, LOW) based on the available evidence

CRITICAL: You must clearly separate FACTS from INFERENCES.
- FACTS are directly observable from the evidence provided (e.g., "Port 5432 is configured with CIDR 0.0.0.0/0")
- INFERENCES are conclusions you draw from the facts (e.g., "The database could be reachable from the public internet")

Never present an inference as a fact. Never invent evidence that was not provided.

Respond with valid JSON matching this structure:
{
  "explanation": "Human-readable summary of the risk",
  "blast_radius": "What systems/users could be affected",
  "operational_impact": "What could go wrong in production",
  "remediation": "Specific steps to fix or mitigate",
  "confidence": "HIGH|MEDIUM|LOW",
  "facts": ["fact 1", "fact 2"],
  "inferences": ["inference 1", "inference 2"]
}

Respond ONLY with the JSON object. No markdown, no explanation outside the JSON."""

RETRYABLE_ERROR_CODES = {"ThrottlingException", "ServiceUnavailableException", "ModelTimeoutException"}
MAX_EVIDENCE_CHARS = 15000


class BedrockAnalyzer:
    def __init__(self, model_id: str | None = None, region: str | None = None, max_tokens: int = 2048) -> None:
        self.model_id = model_id or os.environ.get("RISK_ANALYZER_MODEL", "amazon.nova-lite-v1:0")
        self.max_tokens = max_tokens
        kwargs: dict[str, Any] = {}
        if region:
            kwargs["region_name"] = region
        self._client = boto3.client("bedrock-runtime", **kwargs)

    def analyze(self, evidence: EvidencePackage) -> AIAnalysis:
        prompt = self._build_prompt(evidence)
        try:
            response = self._invoke_with_retry(prompt)
            return self._parse_response(response)
        except Exception:
            logger.exception("Bedrock model invocation failed")
            return AIAnalysis(
                explanation="AI analysis unavailable — model invocation failed. Review the deterministic findings for risk assessment.",
                confidence="LOW",
                facts=[f.finding for f in evidence.findings],
                inferences=["AI analysis could not be completed — rely on deterministic rule findings."],
            )

    def _build_prompt(self, evidence: EvidencePackage) -> str:
        evidence_data = evidence.to_dict()
        serialized = json.dumps(evidence_data, indent=2, default=str)

        if len(serialized) > MAX_EVIDENCE_CHARS:
            for change in evidence_data.get("changes", []):
                if change.get("before") and isinstance(change["before"], dict):
                    change["before"] = {"_keys": list(change["before"].keys()), "_truncated": True}
                if change.get("after") and isinstance(change["after"], dict):
                    change["after"] = {"_keys": list(change["after"].keys()), "_truncated": True}
            serialized = json.dumps(evidence_data, indent=2, default=str)
            serialized += "\n\nNOTE: Resource property details were truncated due to size. Focus analysis on the findings."

        return f"""Analyze the following infrastructure change evidence package and provide a structured risk assessment.

EVIDENCE PACKAGE:
{serialized}

Provide your analysis as a JSON object following the required structure."""

    def _invoke_with_retry(self, prompt: str, max_retries: int = 3) -> str:
        last_error = None
        for attempt in range(max_retries):
            try:
                return self._invoke_model(prompt)
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code in RETRYABLE_ERROR_CODES and attempt < max_retries - 1:
                    delay = 2 ** attempt
                    logger.warning("Retryable error %s, attempt %d/%d, waiting %ds", error_code, attempt + 1, max_retries, delay)
                    time.sleep(delay)
                    last_error = e
                else:
                    raise
        raise last_error  # type: ignore[misc]

    def _invoke_model(self, prompt: str) -> str:
        body: dict[str, Any]

        if "anthropic" in self.model_id.lower() or "claude" in self.model_id.lower():
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": self.max_tokens,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": prompt}],
            }
        else:
            body = {
                "inferenceConfig": {"maxTokens": self.max_tokens},
                "system": [{"text": SYSTEM_PROMPT}],
                "messages": [{"role": "user", "content": [{"text": prompt}]}],
            }

        response = self._client.invoke_model(
            modelId=self.model_id,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(body),
        )
        response_body = json.loads(response["body"].read())

        if "content" in response_body and isinstance(response_body["content"], list):
            return response_body["content"][0].get("text", "")
        if "output" in response_body and isinstance(response_body["output"], dict):
            message = response_body["output"].get("message", {})
            content = message.get("content", [])
            if content:
                return content[0].get("text", "")
        return json.dumps(response_body)

    def _parse_response(self, response_text: str) -> AIAnalysis:
        text = response_text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines).strip()

        # Handle trailing text after JSON
        brace_count = 0
        json_end = -1
        for i, ch in enumerate(text):
            if ch == '{':
                brace_count += 1
            elif ch == '}':
                brace_count -= 1
                if brace_count == 0:
                    json_end = i + 1
                    break
        if json_end > 0:
            text = text[:json_end]

        try:
            data = json.loads(text)
            return AIAnalysis.from_dict(data)
        except (json.JSONDecodeError, KeyError, TypeError):
            logger.warning("Failed to parse AI response as structured JSON")
            return AIAnalysis(
                explanation=response_text[:2000],
                confidence="LOW",
                facts=[],
                inferences=["AI response was not in expected structured format — raw text included in explanation."],
            )
