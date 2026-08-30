#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "=== Risk Analyzer CI Pipeline (Local) ==="
echo ""

# Phase 1: Install
echo "[1/4] Installing dependencies..."
source .venv/bin/activate 2>/dev/null || { uv venv .venv && source .venv/bin/activate; }
uv pip install -r requirements-dev.txt -q

# Phase 2: Unit Tests
echo "[2/4] Running unit tests..."
python -m pytest tests/ -v --tb=short
echo ""

# Phase 3: Evaluation
echo "[3/4] Running evaluation scenarios..."
python cli.py eval
echo ""

# Phase 4: Analysis (if templates provided)
BEFORE="${1:-}"
AFTER="${2:-}"
ENV="${3:-development}"

if [ -n "$AFTER" ]; then
    echo "[4/4] Analyzing infrastructure change..."
    ARGS="--after $AFTER --environment $ENV"
    if [ -n "$BEFORE" ]; then
        ARGS="--before $BEFORE $ARGS"
    fi
    python cli.py analyze $ARGS --save --save-evidence --notify
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        echo ""
        echo "PIPELINE RESULT: BLOCKED — change was rejected"
        exit 1
    fi
    echo ""
    echo "PIPELINE RESULT: APPROVED — change is safe to deploy"
else
    echo "[4/4] No templates provided — skipping analysis"
    echo ""
    echo "Usage: $0 [before.yaml] <after.yaml> [environment]"
    echo "  Example: $0 current.yaml proposed.yaml production"
fi

echo ""
echo "=== Pipeline Complete ==="
