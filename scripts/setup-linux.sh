#!/bin/bash
# ViGiL — Linux Setup Script (x86_64 + ARM64)
# Installs all optional analysis tools automatically.
# Supports: Ubuntu/Debian, Fedora/RHEL, Arch/Manjaro
#
# Usage: bash scripts/setup-linux.sh

set -e

ARCH=$(uname -m)   # x86_64 or aarch64
BIN="/usr/local/bin"

CAPA_VERSION="9.4.0"
FLOSS_VERSION="3.1.1"

echo "════════════════════════════════════════"
echo "  ViGiL — Linux Tool Setup"
echo "  Architecture: $ARCH"
echo "════════════════════════════════════════"
echo ""

# ── Detect package manager ───────────────────────────────────────────
if command -v apt &>/dev/null; then
    PKG_MGR="apt"
    UPDATE="sudo apt update -q"
    INSTALL="sudo apt install -y"
    PKG_RIZIN="rizin"
    PKG_UPX="upx-ucl"
    PKG_UNZIP="unzip"
elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
    UPDATE="sudo dnf check-update -q || true"
    INSTALL="sudo dnf install -y"
    PKG_RIZIN="rizin"
    PKG_UPX="upx"
    PKG_UNZIP="unzip"
elif command -v pacman &>/dev/null; then
    PKG_MGR="pacman"
    UPDATE="sudo pacman -Sy"
    INSTALL="sudo pacman -S --noconfirm"
    PKG_RIZIN="rizin"
    PKG_UPX="upx"
    PKG_UNZIP="unzip"
else
    echo "ERROR: Unsupported package manager. Install rizin, upx, unzip manually."
    exit 1
fi

echo "▶ Using package manager: $PKG_MGR"

# ── System tools ────────────────────────────────────────────────────
echo ""
echo "▶ Installing system tools (rizin, upx, unzip)..."
$UPDATE
$INSTALL $PKG_RIZIN $PKG_UPX $PKG_UNZIP curl
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
if [ "$ARCH" = "aarch64" ]; then
    CAPA_URL="https://github.com/mandiant/capa/releases/download/v${CAPA_VERSION}/capa-v${CAPA_VERSION}-linux-arm64.zip"
else
    CAPA_URL="https://github.com/mandiant/capa/releases/download/v${CAPA_VERSION}/capa-v${CAPA_VERSION}-linux.zip"
fi
curl -sL "$CAPA_URL" -o /tmp/capa.zip
unzip -o /tmp/capa.zip -d /tmp/capa_bin/ &>/dev/null
sudo mv /tmp/capa_bin/capa "$BIN/capa"
sudo chmod +x "$BIN/capa"
echo "  ✓ capa $(capa --version)"

# ── FLOSS ───────────────────────────────────────────────────────────
echo ""
echo "▶ Installing FLOSS v${FLOSS_VERSION} (Mandiant FLARE)..."
if [ "$ARCH" = "aarch64" ]; then
    FLOSS_URL="https://github.com/mandiant/flare-floss/releases/download/v${FLOSS_VERSION}/floss-v${FLOSS_VERSION}-linux-arm64.zip"
else
    FLOSS_URL="https://github.com/mandiant/flare-floss/releases/download/v${FLOSS_VERSION}/floss-v${FLOSS_VERSION}-linux.zip"
fi
curl -sL "$FLOSS_URL" -o /tmp/floss.zip
unzip -o /tmp/floss.zip -d /tmp/floss_bin/ &>/dev/null
sudo mv /tmp/floss_bin/floss "$BIN/floss"
sudo chmod +x "$BIN/floss"
echo "  ✓ floss $(floss --version)"

# ── Ollama ──────────────────────────────────────────────────────────
echo ""
echo "▶ Installing Ollama (local LLM)..."
if ! command -v ollama &>/dev/null; then
    curl -fsSL https://ollama.ai/install.sh | sh
fi
ollama pull llama3.2
echo "  ✓ ollama $(ollama --version)"

# ── Summary ─────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════"
echo "  Setup Complete!"
echo ""
echo "  Start ViGiL:"
echo "    cd backend && source venv/bin/activate"
echo "    uvicorn main:app --port 8000 --reload"
echo "    # (in another terminal)"
echo "    cd frontend && npm run dev"
echo "════════════════════════════════════════"
