#!/bin/bash
# ViGiL — Tool Verification Script
# Run after setup to confirm all tools are working.
# Usage: bash scripts/check-tools.sh

echo "════════════════════════════════════════"
echo "  ViGiL — Tool Check"
echo "════════════════════════════════════════"
echo ""

OK="✅"
MISS="❌"

check() {
    local name="$1"
    local cmd="$2"
    local result
    result=$(eval "$cmd" 2>/dev/null | head -1)
    if [ -n "$result" ]; then
        printf "  %s %-12s %s\n" "$OK" "$name" "$result"
    else
        printf "  %s %-12s NOT INSTALLED\n" "$MISS" "$name"
    fi
}

echo "── Runtime ──────────────────────────────"
check "python3"  "python3 --version"
check "node"     "node --version"
check "npm"      "npm --version"

echo ""
echo "── Analysis Tools ───────────────────────"
check "capa"      "capa --version"
check "floss"     "floss --version"
check "rizin"     "rizin --version"
check "upx"       "upx --version"

echo ""
echo "── Python Packages ──────────────────────"
check "pefile"    "python3 -c 'import pefile; print(pefile.__version__)'"
check "speakeasy" "python3 -c 'import speakeasy; print(speakeasy.__version__)'"
check "lief"      "python3 -c 'import lief; print(lief.__version__)'"
check "angr"      "python3 -c 'import angr; print(angr.__version__)'"

echo ""
echo "── LLM Providers ────────────────────────"
check "ollama"    "ollama --version"

# Check Ollama server
if curl -s http://localhost:11434/api/tags &>/dev/null; then
    printf "  %s %-12s running at http://localhost:11434\n" "$OK" "ollama-srv"
else
    printf "  %s %-12s server not running (run: ollama serve)\n" "$MISS" "ollama-srv"
fi

# Check LM Studio server
if curl -s http://localhost:1234/v1/models &>/dev/null; then
    printf "  %s %-12s running at http://localhost:1234\n" "$OK" "lmstudio"
else
    printf "  ⚪ %-12s not running (optional)\n" "lmstudio"
fi

echo ""
echo "── Backend ──────────────────────────────"
if curl -s http://localhost:8000/api/health &>/dev/null; then
    HEALTH=$(curl -s http://localhost:8000/api/health)
    DEMO=$(echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); print('demo' if d.get('demo_mode') else 'REAL')")
    LLM=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('llm_provider','?'))")
    printf "  %s %-12s running | LLM: %s | Mode: %s\n" "$OK" "backend" "$LLM" "$DEMO"
else
    printf "  %s %-12s NOT RUNNING\n" "$MISS" "backend"
fi

echo ""
echo "── Frontend ─────────────────────────────"
if curl -s http://localhost:5173 &>/dev/null; then
    printf "  %s %-12s running at http://localhost:5173\n" "$OK" "frontend"
else
    printf "  %s %-12s NOT RUNNING\n" "$MISS" "frontend"
fi

echo ""
echo "════════════════════════════════════════"
