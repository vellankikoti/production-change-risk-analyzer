from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3

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


class BedrockAnalyzer:
    def __init__(self, model_id: str | None = None, region: str | None = None) -> None:
        self.model_id = model_id or os.environ.get("RISK_ANALYZER_MODEL", "amazon.nova-lite-v1:0")
        self.region = region or os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-west-2"))
        self._client = boto3.client("bedrock-runtime", region_name=self.region)

    def analyze(self, evidence: EvidencePackage) -> AIAnalysis:
        prompt = self._build_prompt(evidence)
        try:
            response = self._invoke_model(prompt)
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
        return f"""Analyze the following infrastructure change evidence package and provide a structured risk assessment.

EVIDENCE PACKAGE:
{json.dumps(evidence_data, indent=2, default=str)}

Provide your analysis as a JSON object following the required structure."""

    def _invoke_model(self, prompt: str) -> str:
        body: dict[str, Any]

        if "anthropic" in self.model_id.lower() or "claude" in self.model_id.lower():
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 2048,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": prompt}],
            }
        else:
            body = {
                "inferenceConfig": {"maxTokens": 2048},
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

        try:
            data = json.loads(text)
            return AIAnalysis.from_dict(data)
        except (json.JSONDecodeError, KeyError, TypeError):
            logger.warning("Failed to parse AI response as structured JSON")
            return AIAnalysis(
                explanation=text[:2000],
                confidence="LOW",
                facts=[],
                inferences=["AI response was not in expected structured format — raw text included in explanation."],
            )
