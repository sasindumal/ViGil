# ViGiL — Cross-Platform Compatibility

ViGiL runs on **macOS** and **Linux**. This guide covers platform-specific differences.

---

## Compatibility Matrix

| Component | macOS (Apple Silicon) | macOS (Intel) | Linux (x86_64) | Linux (ARM64) |
|-----------|:-------------------:|:-------------:|:--------------:|:-------------:|
| Backend (Python/FastAPI) | ✅ | ✅ | ✅ | ✅ |
| Frontend (Vite/React) | ✅ | ✅ | ✅ | ✅ |
| CAPA | ✅ arm64 binary | ✅ x86_64 binary | ✅ x86_64 binary | ✅ arm64 binary |
| Speakeasy | ⚠️ Python ≤3.11 only | ⚠️ Python ≤3.11 only | ⚠️ Python ≤3.11 only | ⚠️ limited |
| FLOSS | ✅ arm64 binary | ✅ x86_64 binary | ✅ x86_64 binary | ✅ arm64 binary |
| angr | ✅ (slow on arm64) | ✅ | ✅ | ⚠️ limited |
| rizin | ✅ brew | ✅ brew | ✅ apt/dnf | ✅ apt/dnf |
| UPX | ✅ brew | ✅ brew | ✅ apt | ✅ apt |
| LM Studio | ✅ native | ✅ native | ✅ native | ✅ native |
| Ollama | ✅ native | ✅ native | ✅ native | ✅ native |

---

## Known Issues

### Speakeasy + Python 3.12

`speakeasy-emulator 1.5.11` pins `unicorn==1.0.2`, which uses `pkg_resources` and `distutils` — both **removed in Python 3.12**.

**Impact:** Speakeasy will not load on Python 3.12+. ViGiL automatically falls back to heuristic behavioral analysis.

**Workaround options:**
- Run the backend with **Python 3.11** (install via `pyenv` or system package manager)
- Wait for Speakeasy to release a Python 3.12-compatible version
- Heuristic fallback still gives useful behavioral inference from static imports

```bash
# Check your Python version
python3 --version

# Use pyenv to install Python 3.11 (if needed)
pyenv install 3.11.9
pyenv local 3.11.9
python3 -m venv venv   # recreate venv with 3.11
```



---

## Core Setup (Both Platforms)

### Python Requirements

```bash
python3 --version    # Must be 3.11 or higher
```

### Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

These steps are **identical** on macOS and Linux.

---

## Installing Tools — macOS

### Package Manager: Homebrew

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### rizin

```bash
brew install rizin
```

### UPX

```bash
brew install upx
```

### Ollama

```bash
brew install ollama
ollama serve &
ollama pull llama3.2
```

### CAPA (Mandiant — the correct one)

> ⚠️ **Do NOT use `pip install capa`** — that installs a completely unrelated French library.

```bash
# Detect your architecture
ARCH=$(uname -m)   # arm64 = Apple Silicon, x86_64 = Intel

if [ "$ARCH" = "arm64" ]; then
    CAPA_URL="https://github.com/mandiant/capa/releases/download/v9.4.0/capa-v9.4.0-macos-arm64.zip"
else
    CAPA_URL="https://github.com/mandiant/capa/releases/download/v9.4.0/capa-v9.4.0-macos.zip"
fi

curl -L "$CAPA_URL" -o /tmp/capa.zip
unzip /tmp/capa.zip -d /tmp/capa_bin/
mkdir -p ~/bin
cp /tmp/capa_bin/capa ~/bin/capa
chmod +x ~/bin/capa
```

Add `~/bin` to your PATH permanently:

```bash
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# Verify
capa --version
```

### FLOSS (Mandiant)

```bash
ARCH=$(uname -m)

if [ "$ARCH" = "arm64" ]; then
    FLOSS_URL="https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-macos-arm64.zip"
else
    FLOSS_URL="https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-macos.zip"
fi

curl -L "$FLOSS_URL" -o /tmp/floss.zip
unzip /tmp/floss.zip -d /tmp/floss_bin/
cp /tmp/floss_bin/floss ~/bin/floss
chmod +x ~/bin/floss

# Verify
floss --version
```

### Speakeasy

```bash
pip install speakeasy-emulator
python -c "import speakeasy; print('Speakeasy OK')"
```

---

## Installing Tools — Linux

### Package Manager

Choose the commands for your distribution:

| Distro | Package Manager |
|--------|----------------|
| Ubuntu / Debian | `apt` |
| Fedora / RHEL | `dnf` |
| Arch / Manjaro | `pacman` |

### rizin

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y rizin

# Fedora
sudo dnf install -y rizin

# Arch
sudo pacman -S rizin
```

### UPX

```bash
# Ubuntu/Debian
sudo apt install -y upx-ucl

# Fedora
sudo dnf install -y upx

# Arch
sudo pacman -S upx
```

### Ollama

```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.2
```

### CAPA (Mandiant — the correct one)

> ⚠️ **Do NOT use `pip install capa`** — that installs a completely unrelated library.

```bash
# Detect architecture
ARCH=$(uname -m)   # x86_64 or aarch64

if [ "$ARCH" = "aarch64" ]; then
    CAPA_URL="https://github.com/mandiant/capa/releases/download/v9.4.0/capa-v9.4.0-linux-arm64.zip"
else
    CAPA_URL="https://github.com/mandiant/capa/releases/download/v9.4.0/capa-v9.4.0-linux.zip"
fi

curl -L "$CAPA_URL" -o /tmp/capa.zip
unzip /tmp/capa.zip -d /tmp/capa_bin/
sudo mv /tmp/capa_bin/capa /usr/local/bin/capa
sudo chmod +x /usr/local/bin/capa

# Verify
capa --version
```

### FLOSS (Mandiant)

```bash
ARCH=$(uname -m)

if [ "$ARCH" = "aarch64" ]; then
    FLOSS_URL="https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-linux-arm64.zip"
else
    FLOSS_URL="https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-linux.zip"
fi

curl -L "$FLOSS_URL" -o /tmp/floss.zip
unzip /tmp/floss.zip -d /tmp/floss_bin/
sudo mv /tmp/floss_bin/floss /usr/local/bin/floss
sudo chmod +x /usr/local/bin/floss

# Verify
floss --version
```

### Speakeasy

```bash
pip install speakeasy-emulator
python -c "import speakeasy; print('Speakeasy OK')"
```

### LM Studio on Linux

```bash
# Download AppImage from https://lmstudio.ai
chmod +x LM_Studio-*.AppImage
./LM_Studio-*.AppImage
```

---

## One-Command Setup Scripts

### macOS Setup Script

```bash
#!/bin/bash
# Save as: scripts/setup-macos.sh

set -e
ARCH=$(uname -m)
BIN="$HOME/bin"
mkdir -p "$BIN"

echo "==> Installing Homebrew tools..."
brew install rizin upx ollama

echo "==> Installing Python tools..."
cd backend && source venv/bin/activate
pip install speakeasy-emulator

echo "==> Downloading CAPA v9.4.0..."
if [ "$ARCH" = "arm64" ]; then
    CAPA_URL="https://github.com/mandiant/capa/releases/download/v9.4.0/capa-v9.4.0-macos-arm64.zip"
else
    CAPA_URL="https://github.com/mandiant/capa/releases/download/v9.4.0/capa-v9.4.0-macos.zip"
fi
curl -L "$CAPA_URL" -o /tmp/capa.zip && unzip -o /tmp/capa.zip -d /tmp/capa_bin/ && cp /tmp/capa_bin/capa "$BIN/capa" && chmod +x "$BIN/capa"

echo "==> Downloading FLOSS v3.1.1..."
if [ "$ARCH" = "arm64" ]; then
    FLOSS_URL="https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-macos-arm64.zip"
else
    FLOSS_URL="https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-macos.zip"
fi
curl -L "$FLOSS_URL" -o /tmp/floss.zip && unzip -o /tmp/floss.zip -d /tmp/floss_bin/ && cp /tmp/floss_bin/floss "$BIN/floss" && chmod +x "$BIN/floss"

# Ensure ~/bin is in PATH
if ! grep -q 'HOME/bin' ~/.zshrc 2>/dev/null; then
    echo 'export PATH="$HOME/bin:$PATH"' >> ~/.zshrc
fi

echo ""
echo "==> Pulling Ollama model..."
ollama serve &>/dev/null & sleep 2
ollama pull llama3.2

echo ""
echo "===================================="
echo "  Setup complete!"
echo "  Run: source ~/.zshrc"
echo "  Then: capa --version && floss --version"
echo "===================================="
```

### Linux Setup Script

```bash
#!/bin/bash
# Save as: scripts/setup-linux.sh

set -e
ARCH=$(uname -m)

echo "==> Installing system tools..."
if command -v apt &>/dev/null; then
    sudo apt update && sudo apt install -y rizin upx-ucl unzip curl
elif command -v dnf &>/dev/null; then
    sudo dnf install -y rizin upx unzip curl
elif command -v pacman &>/dev/null; then
    sudo pacman -Sy --noconfirm rizin upx unzip curl
fi

echo "==> Installing Python tools..."
cd backend && source venv/bin/activate
pip install speakeasy-emulator

echo "==> Downloading CAPA v9.4.0..."
if [ "$ARCH" = "aarch64" ]; then
    CAPA_URL="https://github.com/mandiant/capa/releases/download/v9.4.0/capa-v9.4.0-linux-arm64.zip"
else
    CAPA_URL="https://github.com/mandiant/capa/releases/download/v9.4.0/capa-v9.4.0-linux.zip"
fi
curl -L "$CAPA_URL" -o /tmp/capa.zip && unzip -o /tmp/capa.zip -d /tmp/capa_bin/
sudo mv /tmp/capa_bin/capa /usr/local/bin/capa && sudo chmod +x /usr/local/bin/capa

echo "==> Downloading FLOSS v3.1.1..."
if [ "$ARCH" = "aarch64" ]; then
    FLOSS_URL="https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-linux-arm64.zip"
else
    FLOSS_URL="https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-linux.zip"
fi
curl -L "$FLOSS_URL" -o /tmp/floss.zip && unzip -o /tmp/floss.zip -d /tmp/floss_bin/
sudo mv /tmp/floss_bin/floss /usr/local/bin/floss && sudo chmod +x /usr/local/bin/floss

echo "==> Installing Ollama..."
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.2

echo ""
echo "===================================="
echo "  Setup complete!"
echo "  capa --version && floss --version"
echo "===================================="
```

---

## Important: CAPA Is NOT a pip Package

The `capa` package on PyPI (`pip install capa`) is **NOT** Mandiant's CAPA.  
It is an unrelated 0.1 library. Always download CAPA as a binary from:

> **https://github.com/mandiant/capa/releases**

If you accidentally installed it:

```bash
pip uninstall capa -y
```

Then follow the binary install steps above.

---

## Platform-Specific Notes

### macOS (Apple Silicon — M1/M2/M3/M4)

- All tools have native `arm64` binaries — no Rosetta needed
- Speakeasy and CAPA work natively
- LM Studio has excellent Apple Silicon GPU support

### macOS (Intel — x86_64)

- Use the non-arm64 binary download URLs
- All tools fully supported

### Linux (x86_64)

- Most common deployment target
- All tools fully supported
- Use `apt`/`dnf`/`pacman` for system packages

### Linux (ARM64 — Raspberry Pi, AWS Graviton, etc.)

- CAPA and FLOSS have arm64 binaries
- Speakeasy may have emulation limitations (it emulates x86 code, which requires Unicorn on ARM host)
- LM Studio supports Linux ARM64

---

## Verify Everything Is Working

Run this after setup:

```bash
echo "=== ViGiL Tool Check ==="
echo -n "Python:    "; python3 --version
echo -n "Node:      "; node --version
echo -n "capa:      "; capa --version 2>/dev/null | head -1 || echo "NOT INSTALLED"
echo -n "floss:     "; floss --version 2>/dev/null | head -1 || echo "NOT INSTALLED"
echo -n "rizin:     "; rizin --version 2>/dev/null | head -1 || echo "NOT INSTALLED"
echo -n "upx:       "; upx --version 2>/dev/null | head -1 || echo "NOT INSTALLED"
echo -n "speakeasy: "; python3 -c "import speakeasy; print('OK')" 2>/dev/null || echo "NOT INSTALLED"
echo -n "ollama:    "; ollama --version 2>/dev/null || echo "NOT INSTALLED"
echo "========================"
```
