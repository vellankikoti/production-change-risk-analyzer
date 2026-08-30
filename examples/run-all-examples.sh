#!/usr/bin/env bash
# Run all examples and show expected vs actual results.
# Usage: bash examples/run-all-examples.sh

cd "$(dirname "$0")/.."

GREEN='\033[0;32m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

pass=0
fail=0

run_example() {
    local name="$1"
    local expected_decision="$2"
    shift 2

    echo ""
    echo -e "${BOLD}━━━ Example: ${name} ━━━${NC}"
    echo "Command: $*"

    local output
    output=$("$@" --format json 2>/dev/null) || true

    local actual_decision actual_score actual_level finding_count
    actual_decision=$(echo "$output" | python3 -c "import sys,json; print(json.load(sys.stdin)['decision'])" 2>/dev/null) || actual_decision="ERROR"
    actual_score=$(echo "$output" | python3 -c "import sys,json; print(json.load(sys.stdin)['risk_score'])" 2>/dev/null) || actual_score="?"
    actual_level=$(echo "$output" | python3 -c "import sys,json; print(json.load(sys.stdin)['risk_level'])" 2>/dev/null) || actual_level="?"
    finding_count=$(echo "$output" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('evidence',{}).get('findings',[])))" 2>/dev/null) || finding_count="?"

    echo "Result: ${actual_level} / ${actual_decision} (score: ${actual_score}, findings: ${finding_count})"
    echo "Expected: ${expected_decision}"

    if [ "$actual_decision" = "$expected_decision" ]; then
        echo -e "${GREEN}PASS${NC}"
        pass=$((pass + 1))
    else
        echo -e "${RED}FAIL — expected ${expected_decision}, got ${actual_decision}${NC}"
        fail=$((fail + 1))
    fi
}

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   Production Change Risk Analyzer — Example Scenarios   ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

run_example \
    "1: Public Database Exposure" \
    "BLOCK" \
    python cli.py analyze --after examples/01-public-database.yaml --no-ai

run_example \
    "2: IAM Full Admin Access" \
    "BLOCK" \
    python cli.py analyze --after examples/02-iam-admin-access.yaml --no-ai

run_example \
    "3: Reduced Availability (before/after diff)" \
    "BLOCK" \
    python cli.py analyze --before examples/03-secure-baseline.yaml --after examples/03-reduced-availability.yaml --environment production --no-ai

run_example \
    "4: Missing Encryption & Logging" \
    "BLOCK" \
    python cli.py analyze --after examples/04-encryption-logging-gaps.yaml --no-ai

run_example \
    "5: Safe Changes (should pass)" \
    "APPROVE" \
    python cli.py analyze --after examples/05-safe-changes.yaml --no-ai

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
total=$((pass + fail))
echo -e "Results: ${GREEN}${pass} passed${NC}, ${RED}${fail} failed${NC} out of ${total}"

if [ "$fail" -eq 0 ]; then
    echo -e "${GREEN}All examples produced expected results.${NC}"
else
    echo -e "${RED}Some examples did not match expectations.${NC}"
    exit 1
fi
