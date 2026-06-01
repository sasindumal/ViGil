#!/bin/bash
# ViGiL — Tool Verification Script
# Run after setup to confirm all tools are working.
# Usage: bash scripts/check-tools.sh

# Prepend ~/bin so capa/floss are found even without sourcing .zshrc
export PATH="$HOME/bin:$PATH"

echo "════════════════════════════════════════"
echo "  ViGiL — Tool Check"
echo "════════════════════════════════════════"
echo ""

OK="✅"
MISS="❌"

# Use the venv Python for package checks — NOT the system Python
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="$SCRIPT_DIR/../backend/venv/bin/python"
if [ ! -f "$VENV_PY" ]; then
    VENV_PY="python3"
    echo "  ⚠  No venv found — falling back to system python3"
fi

# Check if a command exists (does NOT run it — avoids Gatekeeper hangs on unknown binaries)
check_exists() {
    local name="$1"
    local bin="$2"
    if command -v "$bin" &>/dev/null; then
        # Run with a 3s background timeout to avoid hangs
        result=$(("$bin" --version 2>/dev/null || "$bin" -v 2>/dev/null || echo "") &
                  PID=$!; sleep 3; kill $PID 2>/dev/null)
        result=$(echo "$result" | head -1)
        printf "  %s %-12s %s\n" "$OK" "$name" "${result:-installed}"
    else
        printf "  %s %-12s NOT INSTALLED\n" "$MISS" "$name"
    fi
}

# Simpler check using which only (no execution)
check_binary() {
    local name="$1"
    local bin="$2"
    local version_cmd="${3:-$bin --version}"
    if command -v "$bin" &>/dev/null; then
        printf "  %s %-12s found at %s\n" "$OK" "$name" "$(command -v "$bin")"
    else
        printf "  %s %-12s NOT INSTALLED\n" "$MISS" "$name"
    fi
}

check_py() {
    local name="$1"
    local module="$2"
    local version_expr="${3:-__version__}"
    local result
    result=$("$VENV_PY" -c "import $module; print($module.$version_expr)" 2>/dev/null)
    if [ -n "$result" ]; then
        printf "  %s %-12s %s\n" "$OK" "$name" "$result"
    else
        printf "  %s %-12s NOT INSTALLED\n" "$MISS" "$name"
    fi
}

echo "── Runtime ──────────────────────────────"
printf "  %s %-12s %s\n" "$OK" "sys python" "$(python3 --version 2>/dev/null)"
printf "  %s %-12s %s\n" "$OK" "venv python" "$("$VENV_PY" --version 2>/dev/null)"
printf "  %s %-12s %s\n" "$OK" "node" "$(node --version 2>/dev/null)"
printf "  %s %-12s %s\n" "$OK" "npm" "$(npm --version 2>/dev/null)"

echo ""
echo "── Analysis Tools ───────────────────────"
check_binary "capa"   "capa"
check_binary "floss"  "floss"
check_binary "rizin"  "rizin"
check_binary "upx"    "upx"

echo ""
echo "── Python Packages (venv) ───────────────"
check_py "pefile"  "pefile"  "__version__"
check_py "lief"    "lief"    "__version__"
check_py "angr"    "angr"    "__version__"
check_py "crewai"  "crewai"  "__version__"
check_py "aiosqlite" "aiosqlite" "__version__"
check_py "litellm" "litellm" "__version__"

# Speakeasy has no __version__ — check instantiation
if "$VENV_PY" -c "import speakeasy; speakeasy.Speakeasy()" 2>/dev/null; then
    printf "  %s %-12s OK (full emulation)\n" "$OK" "speakeasy"
elif "$VENV_PY" -c "import speakeasy" 2>/dev/null; then
    printf "  ⚠️  %-12s installed but init failed (heuristic fallback active)\n" "speakeasy"
else
    printf "  %s %-12s NOT INSTALLED\n" "$MISS" "speakeasy"
fi

echo ""
echo "── LLM Providers ────────────────────────"
if command -v ollama &>/dev/null; then
    printf "  %s %-12s found at %s\n" "$OK" "ollama" "$(command -v ollama)"
else
    printf "  %s %-12s NOT INSTALLED\n" "$MISS" "ollama"
fi

if curl -s --max-time 2 http://localhost:11434/api/tags &>/dev/null; then
    printf "  %s %-12s running at http://localhost:11434\n" "$OK" "ollama-srv"
else
    printf "  %s %-12s server not running (run: ollama serve)\n" "$MISS" "ollama-srv"
fi

if curl -s --max-time 2 http://localhost:1234/v1/models &>/dev/null; then
    printf "  %s %-12s running at http://localhost:1234\n" "$OK" "lmstudio"
else
    printf "  ⚪ %-12s not running (optional)\n" "lmstudio"
fi

echo ""
echo "── Backend ──────────────────────────────"
if curl -s --max-time 2 http://localhost:8000/api/health &>/dev/null; then
    HEALTH=$(curl -s http://localhost:8000/api/health)
    DEMO=$(echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); print('demo' if d.get('demo_mode') else 'REAL')" 2>/dev/null)
    LLM=$(echo "$HEALTH"  | python3 -c "import sys,json; print(json.load(sys.stdin).get('llm_provider','?'))" 2>/dev/null)
    printf "  %s %-12s running | LLM: %s | Mode: %s\n" "$OK" "backend" "$LLM" "$DEMO"
else
    printf "  %s %-12s NOT RUNNING\n" "$MISS" "backend"
fi

echo ""
echo "── Frontend ─────────────────────────────"
if curl -s --max-time 2 http://localhost:5173 &>/dev/null; then
    printf "  %s %-12s running at http://localhost:5173\n" "$OK" "frontend"
else
    printf "  %s %-12s NOT RUNNING\n" "$MISS" "frontend"
fi

echo ""
echo "════════════════════════════════════════"
