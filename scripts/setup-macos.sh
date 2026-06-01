#!/bin/bash
# ViGiL — macOS Setup Script (Apple Silicon + Intel)
# Installs all optional analysis tools automatically.
#
# Usage: bash scripts/setup-macos.sh

set -e

ARCH=$(uname -m)
BIN="$HOME/bin"
mkdir -p "$BIN"

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
pip install speakeasy-emulator -q
python -c "import speakeasy; print('  ✓ speakeasy', speakeasy.__version__)"

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
export PATH="$BIN:$PATH"
echo "  ✓ capa $("$BIN/capa" --version)"

# ── FLOSS ───────────────────────────────────────────────────────────
echo ""
echo "▶ Installing FLOSS v${FLOSS_VERSION} (Mandiant FLARE)..."
if [ "$ARCH" = "arm64" ]; then
    FLOSS_URL="https://github.com/mandiant/flare-floss/releases/download/v${FLOSS_VERSION}/floss-v${FLOSS_VERSION}-macos-arm64.zip"
else
    FLOSS_URL="https://github.com/mandiant/flare-floss/releases/download/v${FLOSS_VERSION}/floss-v${FLOSS_VERSION}-macos.zip"
fi
curl -sL "$FLOSS_URL" -o /tmp/floss.zip
unzip -o /tmp/floss.zip -d /tmp/floss_bin/ &>/dev/null
cp /tmp/floss_bin/floss "$BIN/floss" && chmod +x "$BIN/floss"
echo "  ✓ floss $("$BIN/floss" --version)"


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
