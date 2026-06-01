#!/bin/bash
# ViGiL — macOS Setup Script (Apple Silicon + Intel)
# Installs all optional analysis tools automatically.
#
# Usage: bash scripts/setup-macos.sh

# NOTE: We do NOT use 'set -e' so that one step failing doesn't abort others

ARCH=$(uname -m)
BIN="$HOME/bin"
mkdir -p "$BIN"
export PATH="$BIN:$PATH"   # ensure ~/bin binaries are usable immediately in this session

CAPA_VERSION="9.4.0"
FLOSS_VERSION="3.1.1"

echo "════════════════════════════════════════"
echo "  ViGiL — macOS Tool Setup"
echo "  Architecture: $ARCH"
echo "════════════════════════════════════════"
echo ""

# ── Homebrew tools ──────────────────────────────────────────────────
echo "▶ Installing Homebrew tools (rizin, upx)..."
if ! command -v brew &>/dev/null; then
    echo "  Homebrew not found. Install from https://brew.sh first."
    exit 1
fi
brew install rizin upx
echo "  ✓ rizin $(rizin --version 2>/dev/null | head -1)"
echo "  ✓ upx $(upx --version 2>/dev/null | head -1)"

# ── Python tools ────────────────────────────────────────────────────
echo ""
echo "▶ Installing Python analysis packages..."
if [ -f "backend/venv/bin/activate" ]; then
    source backend/venv/bin/activate
fi

# setuptools 69.5.1 exposes pkg_resources — required by speakeasy's unicorn==1.0.2 dependency
pip install "setuptools==69.5.1" --force-reinstall -q
pip install speakeasy-emulator -q

# Verify speakeasy (non-fatal — emulation falls back to heuristics if broken)
if python -c "import speakeasy; speakeasy.Speakeasy()" 2>/dev/null; then
    echo "  ✓ speakeasy OK"
else
    echo "  ⚠ speakeasy installed but emulation may fall back to heuristics"
fi

# ── CAPA ────────────────────────────────────────────────────────────
echo ""
echo "▶ Installing CAPA v${CAPA_VERSION} (Mandiant FLARE)..."
if [ "$ARCH" = "arm64" ]; then
    CAPA_URL="https://github.com/mandiant/capa/releases/download/v${CAPA_VERSION}/capa-v${CAPA_VERSION}-macos-arm64.zip"
else
    CAPA_URL="https://github.com/mandiant/capa/releases/download/v${CAPA_VERSION}/capa-v${CAPA_VERSION}-macos.zip"
fi
curl -sL "$CAPA_URL" -o /tmp/capa.zip
unzip -o /tmp/capa.zip -d /tmp/capa_bin/ &>/dev/null
cp /tmp/capa_bin/capa "$BIN/capa" && chmod +x "$BIN/capa"
# Remove macOS quarantine so the binary can run without Gatekeeper prompt
xattr -d com.apple.quarantine "$BIN/capa" 2>/dev/null || true
export PATH="$BIN:$PATH"
echo "  ✓ capa installed at $BIN/capa"

# ── FLOSS ────────────────────────────────────────────────────
echo ""
echo "▶ Installing FLOSS v${FLOSS_VERSION} (Mandiant FLARE)..."
# FLOSS ships a single universal macOS binary (supports arm64 + x86_64)
curl -sL "https://github.com/mandiant/flare-floss/releases/download/v${FLOSS_VERSION}/floss-v${FLOSS_VERSION}-macos.zip" -o /tmp/floss.zip
unzip -o /tmp/floss.zip -d /tmp/floss_bin/ &>/dev/null
cp /tmp/floss_bin/floss "$BIN/floss" && chmod +x "$BIN/floss"
# Remove macOS quarantine so the binary can run without Gatekeeper prompt
xattr -d com.apple.quarantine "$BIN/floss" 2>/dev/null || true
export PATH="$BIN:$PATH"
echo "  ✓ floss installed at $BIN/floss"


# ── PATH ────────────────────────────────────────────────────────────
echo ""
echo "▶ Updating PATH..."
if ! grep -q 'HOME/bin' ~/.zshrc 2>/dev/null; then
    echo 'export PATH="$HOME/bin:$PATH"' >> ~/.zshrc
    echo "  Added ~/bin to ~/.zshrc"
else
    echo "  ~/bin already in ~/.zshrc"
fi

# ── Summary ─────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════"
echo "  Setup Complete!"
echo ""
echo "  Run: source ~/.zshrc"
echo "  Then start ViGiL:"
echo "    cd backend && source venv/bin/activate"
echo "    uvicorn main:app --port 8000 --reload"
echo "    # (in another terminal)"
echo "    cd frontend && npm run dev"
echo "════════════════════════════════════════"
