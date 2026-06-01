# ViGiL — Setup Guide

## Development Setup (Recommended)

### Step 1: Clone Repository

```bash
git clone https://github.com/your-org/ViGiL.git
cd ViGiL
```

### Step 2: Configure Environment

```bash
cp .env.example .env
```

Edit `.env`:

```env
# Minimum configuration (demo mode)
LLM_PROVIDER=openai
OPENAI_API_KEY=your_openai_api_key   # Required for LLM features

# Or use local Ollama (no API key)
LLM_PROVIDER=ollama
OLLAMA_MODEL=llama3.2
```

### Step 3: Backend

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start server
python main.py
```

Backend runs on: http://localhost:8000  
API docs: http://localhost:8000/api/docs

### Step 4: Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend runs on: http://localhost:5173

---

## Installing Optional Analysis Tools

For full analysis capability, install these tools:

### CAPA (Capability Detection)

```bash
pip install capa
# Verify: capa --version
```

### FLOSS (String Recovery)

Download binary from: https://github.com/mandiant/flare-floss/releases

```bash
# macOS/Linux
chmod +x floss
sudo mv floss /usr/local/bin/
# Verify: floss --version
```

### Speakeasy (Emulation)

```bash
pip install speakeasy-emulator
# Verify: python -c "import speakeasy; print('OK')"
```

### angr (CFG Extraction)

```bash
pip install angr
# Note: Large install (~2GB). Use Docker if preferred.
```

### rizin (Fallback RE)

```bash
# macOS
brew install rizin

# Linux (Debian/Ubuntu)
sudo apt install rizin

# Verify: rizin --version
```

### UPX (Unpacking)

```bash
# macOS
brew install upx

# Linux
sudo apt install upx
```

---

## LLM Configuration

### OpenAI (Cloud)

```env
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o
```

### Google Gemini (Cloud)

```env
LLM_PROVIDER=gemini
GOOGLE_API_KEY=AIza...
GEMINI_MODEL=gemini-2.0-flash
```

### Ollama (Local, Free)

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model
ollama pull llama3.2

# Start Ollama (auto-starts on macOS)
ollama serve
```

```env
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2
```

---

## Threat Intelligence API Keys

All threat intel APIs are **optional**. Without keys, demo mode provides realistic mock data.

### VirusTotal (Free tier: 4 requests/minute)

1. Register at https://www.virustotal.com/gui/join-us
2. Get API key from profile settings

```env
VIRUSTOTAL_API_KEY=your_key
```

### MalwareBazaar (Free)

1. Register at https://bazaar.abuse.ch/account/
2. Get API key from account settings

```env
MALWAREBAZAAR_API_KEY=your_key
```

### AbuseIPDB (Free tier: 1000 checks/day)

1. Register at https://www.abuseipdb.com/account/api
2. Create API key

```env
ABUSEIPDB_API_KEY=your_key
```

### AlienVault OTX (Free)

1. Register at https://otx.alienvault.com/
2. Get API key from account settings

```env
ALIENVAULT_OTX_API_KEY=your_key
```

---

## Uploading Test Samples

> ⚠️ **Safety Note**: Only upload samples in isolated environments. The system does NOT execute files, but use caution with real malware samples.

For testing without real malware, create a test PE:

```bash
# Create a minimal valid PE file for testing
python -c "
import struct

# Minimal MZ + PE header
mz = b'MZ' + b'\\x00' * 62 + struct.pack('<I', 64)  # e_lfanew = 64
pe = b'PE\\x00\\x00'  # PE signature
coff = struct.pack('<HHIIIHH', 0x8664, 0, 0, 0, 0, 0, 0)  # COFF header
with open('test_sample.exe', 'wb') as f:
    f.write(mz + pe + coff + b'\\x00' * 512)
print('Created test_sample.exe')
"
```

Upload `test_sample.exe` to test the full pipeline.

---

## Troubleshooting

### Backend won't start

```bash
# Check Python version
python --version  # Should be 3.11+

# Reinstall with verbose
pip install -r requirements.txt -v
```

### WebSocket not connecting

Ensure backend is running and CORS is not blocked. In development, the Vite proxy handles this automatically.

### LLM returning fallback responses

Check your LLM provider credentials in `.env`. Verify connectivity:

```bash
# OpenAI
curl https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY"

# Ollama
curl http://localhost:11434/api/tags
```

### angr install fails

```bash
# Try with system dependencies first
pip install angr --no-build-isolation

# Or use conda
conda install -c angr angr
```
