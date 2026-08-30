#!/bin/bash
# Source this file to set environment variables for the risk analyzer
# Usage: source setup-env.sh

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION="${AWS_REGION:-$(aws configure get region 2>/dev/null)}"
if [ -z "$REGION" ]; then
  echo "ERROR: No AWS region configured. Set AWS_REGION or run 'aws configure'."
  return 1 2>/dev/null || exit 1
fi

export RISK_ANALYZER_TABLE="risk-analyzer-reports-dev"
export RISK_ANALYZER_BUCKET="risk-analyzer-evidence-${ACCOUNT_ID}-dev"
export RISK_ANALYZER_SNS_TOPIC="arn:aws:sns:${REGION}:${ACCOUNT_ID}:risk-analyzer-alerts-dev"
export RISK_ANALYZER_MODEL="amazon.nova-lite-v1:0"
export AWS_REGION="${REGION}"

echo "Environment configured:"
echo "  Table:  ${RISK_ANALYZER_TABLE}"
echo "  Bucket: ${RISK_ANALYZER_BUCKET}"
echo "  SNS:    ${RISK_ANALYZER_SNS_TOPIC}"
echo "  Model:  ${RISK_ANALYZER_MODEL}"
echo "  Region: ${AWS_REGION}"
