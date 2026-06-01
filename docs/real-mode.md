# ViGiL — Real Mode Configuration Guide

> **By default**, ViGiL runs in **demo/mock mode** — no API keys required, no tools needed. Every agent still runs real analysis logic, but external calls (VirusTotal, LLMs, etc.) return realistic mock data so you can explore the full platform immediately.
>
> This guide explains how to switch each layer to real data, one at a time.

---

## Overview — The 4 Mock Layers

| Layer | Mock Behaviour | What Makes It Real |
|-------|---------------|-------------------|
| **Threat Intelligence** | Returns hardcoded "42/73, RedLine" | Add API keys to `.env` |
| **LLM Analysis** | Returns a static template sentence | Set `LLM_PROVIDER` + API key or install Ollama/LM Studio |
| **Capability Detection** | Guesses from import table | Install `capa` binary |
| **Behavioral Emulation** | Infers from static imports | Install `speakeasy-emulator` |
| **CFG Extraction** | Returns empty function list | Install `angr` or `rizin` |
| **String Recovery** | Uses system `strings` binary | Install FLOSS for obfuscated strings |
| **Unpacking** | Detects signatures only | Install UPX binary |

You can enable any subset — they are all independent.

---

## Step 1 — Edit Your `.env` File

All configuration lives in `.env` at the project root. Copy the example if you haven't already:

```bash
cd /path/to/ViGiL
cp .env.example .env
```

Then open `.env` and fill in the values you want. A restart of the backend is required after changes.

---

## Layer 1: Threat Intelligence (API Keys)

### How Mock Works

When all four keys are empty, `run_threat_intel()` short-circuits and returns:

```python
# agents/threat_intel.py
if not settings.threat_intel_enabled:   # True when all keys are blank
    return ThreatIntelResult(
        virustotal_detections=42,
        virustotal_total=73,
        known_family="RedLine",
        demo_mode=True,
        ...
    )
```

### How to Enable Real Threat Intel

Add **any one or more** API keys to `.env`. The system automatically uses whichever services have keys configured.

```env
# .env

DEMO_MODE=false

# ── VirusTotal ──────────────────────────────────────────────────────────────
# Free tier: 4 lookups/minute, 500/day
# Sign up: https://www.virustotal.com/gui/join-us
# Get key: https://www.virustotal.com/gui/user/<username>/apikey
VIRUSTOTAL_API_KEY=your_64_char_key_here

# ── MalwareBazaar ───────────────────────────────────────────────────────────
# Free, no rate limit
# Sign up + get key: https://bazaar.abuse.ch/account/
MALWAREBAZAAR_API_KEY=your_key_here

# ── AbuseIPDB ───────────────────────────────────────────────────────────────
# Free tier: 1,000 IP checks/day
# Sign up: https://www.abuseipdb.com/register
# Get key: https://www.abuseipdb.com/account/api
ABUSEIPDB_API_KEY=your_key_here

# ── AlienVault OTX ──────────────────────────────────────────────────────────
# Free, unlimited
# Sign up + get key: https://otx.alienvault.com/ (top-right → API)
ALIENVAULT_OTX_API_KEY=your_key_here
```

### What Changes

| Field | Mock | Real |
|-------|------|------|
| `virustotal_detections` | Always 42 | Actual engine count for this exact file hash |
| `virustotal_total` | Always 73 | Real total engines (usually 72–75) |
| `known_family` | Always "RedLine" | Family name from VT threat classification |
| `malwarebazaar_tags` | Always `["stealer", "credential-theft"]` | Real MBZ community tags |
| `is_known_malware` | Always `true` | Based on VT detections > 5 |
| `demo_mode` flag | `true` | `false` — shown in the report UI |

> **Tip:** Start with just `VIRUSTOTAL_API_KEY`. VirusTotal alone covers the most important threat intel data.

---

## Layer 2: LLM — AI Analysis & Decompilation

Used by two agents:
- **Agent 12 (RAG Intelligence)** — evidence-backed analyst explanation
- **Agent 13 (LLM Decompilation)** — natural-language summaries of decompiled functions

### How Mock Works

When no LLM is configured or the API call fails, it returns:

```
"Analysis based on static evidence: Multiple high-confidence indicators were
detected including evasion techniques, suspicious API usage, and behavioral
patterns consistent with known malware families."
```

### Option A — OpenAI (Best Quality)

```env
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-proj-...
OPENAI_MODEL=gpt-4o          # or gpt-4o-mini for lower cost
```

Install the SDK:

```bash
cd backend && source venv/bin/activate
pip install openai
```

Get a key at: https://platform.openai.com/api-keys

> **Cost estimate:** Each analysis uses ~1,000–2,000 tokens total. At GPT-4o pricing (~$5/1M input tokens), this is less than $0.01 per sample.

### Option B — Google Gemini

```env
LLM_PROVIDER=gemini
GOOGLE_API_KEY=AIzaSy...
GEMINI_MODEL=gemini-2.0-flash   # fast and cheap; or gemini-1.5-pro
```

Install the SDK:

```bash
pip install google-generativeai
```

Get a key at: https://aistudio.google.com/apikey (free tier available)

### Option C — Ollama (Local, Free, No API Key)

Runs entirely on your machine — no internet required for LLM inference.

```env
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2         # 2GB, good quality
# alternatives: mistral, codellama, phi3
```

Install and start Ollama:

```bash
# macOS
brew install ollama
ollama serve &          # starts the local server

# Pull a model (one time)
ollama pull llama3.2    # ~2GB download
```

Verify Ollama is running:

```bash
curl http://localhost:11434/api/tags
# Should return a JSON list of downloaded models
```

> **Recommended:** Ollama with `llama3.2` gives strong technical analysis with zero cost and zero data sharing. Analysis takes ~5–15 seconds per sample on Apple Silicon.

### Option D — LM Studio (Local, Free, No API Key, GUI)

LM Studio provides a desktop app with a built-in model browser and local server. Good choice if you prefer a GUI over a CLI.

**Step 1 — Install LM Studio**

Download from: https://lmstudio.ai  
Available for macOS (Apple Silicon + Intel), Windows, Linux.

**Step 2 — Download a Model**

Inside LM Studio: open the **Discover** tab → search for a model → click Download.  
Recommended for malware analysis (good reasoning, fits in 8GB RAM):

| Model | Size | Notes |
|-------|------|-------|
| `Llama-3.2-3B-Instruct` | 2GB | Fast, light |
| `Llama-3.1-8B-Instruct` | 5GB | Best quality on ≤16GB RAM |
| `Mistral-7B-Instruct` | 4GB | Good general reasoning |
| `Phi-3-mini-4k-instruct` | 2.4GB | Very fast on CPU |

**Step 3 — Start the Local Server**

Inside LM Studio: go to **Local Server** tab → select your model → click **Start Server**.  
Default URL: `http://localhost:1234/v1`

**Step 4 — Configure `.env`**

```env
LLM_PROVIDER=lmstudio
LMSTUDIO_BASE_URL=http://localhost:1234/v1

# IMPORTANT: this must match exactly the model name shown in LM Studio's
# Local Server tab — copy it from the dropdown, e.g.:
LMSTUDIO_MODEL=lmstudio-community/Meta-Llama-3.1-8B-Instruct-GGUF
```

> **How to find the exact model name:** In LM Studio → Local Server tab, the model identifier is shown beneath the model dropdown. Copy that full string into `LMSTUDIO_MODEL`.

**No SDK install needed** — LM Studio's API is OpenAI-compatible, and the `openai` Python package is already installed in the venv.

---

## Layer 3: Capability Detection (CAPA)

**Agent 4 (Capability Detection)** — detects what the malware *can do*.

### How Mock Works

Without CAPA, the agent scans the PE import table for known suspicious APIs and makes rough guesses:

```
CreateRemoteThread → "process injection" (guessed)
CryptEncrypt       → "ransomware" (guessed)
```

### How to Enable Real CAPA

CAPA uses 700+ rules from Mandiant's FLARE team to precisely identify capabilities.

```bash
# Install via pip (recommended)
pip install capa

# Verify
capa --version
```

Or download the standalone binary from:  
https://github.com/mandiant/capa/releases

```bash
# macOS (binary)
chmod +x capa
sudo mv capa /usr/local/bin/
```

### What Changes

| Capability | Mock | Real CAPA |
|-----------|------|-----------|
| Detection method | Import table keywords | 700+ behavioral rules |
| False positives | High (any `CryptEncrypt` = ransomware) | Low (rule requires full behavior sequence) |
| Coverage | ~8 capability categories | 200+ fine-grained categories |
| Example output | `"ransomware"` | `"encrypt files on Windows"`, `"use AES via WinCrypt"` |

---

## Layer 4: Behavioral Emulation (Speakeasy)

**Agent 7 (Emulation Analysis)** — runs the code without executing it.

### How Mock Works

Without Speakeasy, the agent reads the PE import table and *infers* likely behavior:

```
InternetOpenUrl → assumes "network beaconing"
RegSetValueEx   → assumes "registry persistence"
```

### How to Enable Real Emulation

```bash
pip install speakeasy-emulator
```

Verify:

```bash
python -c "import speakeasy; print('Speakeasy OK')"
```

### What Changes

Real Speakeasy **actually executes** the malware's code in a sandboxed emulator (no real OS calls):

| Artifact | Mock | Real Speakeasy |
|---------|------|---------------|
| `files_created` | Inferred from imports | Actual `CreateFile` calls traced |
| `registry_keys_created` | Inferred | Actual `RegSetValueEx` calls with real paths |
| `domains_contacted` | Inferred | Actual DNS/HTTP calls resolved |
| `processes_created` | Inferred | Actual `CreateProcess` calls |
| `network_connections` | Inferred | Actual socket operations with IPs + ports |

> **Note:** Speakeasy emulation is safe — it does not execute any real syscalls. It intercepts all Windows API calls and returns emulated responses.

---

## Layer 5: CFG Extraction (angr / rizin)

**Agent 5 (CFG Extraction)** — builds a control flow graph of the binary.

### How Mock Works

Without any CFG tool, the agent returns an empty result:

```json
{ "function_count": 0, "suspicious_functions": [] }
```

### Option A — angr (Full Analysis)

```bash
pip install angr    # Warning: large install (~2GB, takes 10–20 min)
```

angr performs deep static analysis and can handle packed or obfuscated binaries.

### Option B — rizin (Fast, Lightweight)

```bash
# macOS
brew install rizin

# Linux
sudo apt install rizin      # Ubuntu/Debian
sudo dnf install rizin      # Fedora

# Verify
rizin --version
```

rizin is much faster than angr and works well for most binaries.

### What Changes

| Field | Mock | Real CFG |
|-------|------|---------|
| `function_count` | 0 | Actual function count (hundreds to thousands) |
| `avg_complexity` | 0.0 | Cyclomatic complexity score per function |
| `suspicious_functions` | Empty | Functions with high complexity or unusual patterns |
| CFG file | Not generated | `cfg.json` and `callgraph.json` saved |

---

## Layer 6: String Recovery (FLOSS)

**Agent 2 (Static Analysis)** — extracts strings from the binary.

### How Mock Works

The agent falls back to the system `strings` binary (finds plain ASCII/Unicode). This **misses**:

- Stack strings (built character by character at runtime)
- Encoded strings (XOR, base64 constructed in code)
- Wide-character strings assembled dynamically

### How to Enable FLOSS

Download the binary from:  
https://github.com/mandiant/flare-floss/releases

```bash
# macOS (Apple Silicon)
curl -L https://github.com/mandiant/flare-floss/releases/latest/download/floss-v3.1.0-macos-arm64.zip -o floss.zip
unzip floss.zip
chmod +x floss
sudo mv floss /usr/local/bin/

# Verify
floss --version
```

FLOSS is auto-detected — it's tried before `strings` in the fallback chain.

---

## Layer 7: Unpacking (UPX)

**Agent 3 (Unpacking)** — attempts to unpack packed executables.

Currently detects UPX-packed binaries via signature, but needs the UPX binary to actually decompress them.

```bash
# macOS
brew install upx

# Linux
sudo apt install upx

# Verify
upx --version
```

---

## Recommended Minimal Real Setup

For the best results with the least effort:

```bash
# 1. Install tools
pip install capa speakeasy-emulator
brew install rizin upx

# Install Ollama (free LLM)
brew install ollama
ollama pull llama3.2
```

```env
# .env
DEMO_MODE=false
LLM_PROVIDER=ollama
OLLAMA_MODEL=llama3.2
VIRUSTOTAL_API_KEY=your_free_vt_key
```

```bash
# 2. Restart backend
cd backend && source venv/bin/activate
uvicorn main:app --port 8000 --reload
```

This gives you:
- ✅ Real VT detections for every submitted hash
- ✅ Real capability detection via CAPA
- ✅ Real behavioral emulation via Speakeasy
- ✅ Real CFG via rizin
- ✅ Real LLM explanations via local Llama 3.2 (free, private)

---

## Verifying Real Mode is Active

After restarting the backend, check the startup logs:

```
════════════════════════════════════════════════════════════
  ViGiL — Multi-Agent Malware Analysis Platform v1.0.0
════════════════════════════════════════════════════════════
  LLM Provider: ollama            ← should NOT say "no key"
  Threat Intel: ENABLED           ← should NOT say "DEMO MODE"
  Vector Store: faiss
════════════════════════════════════════════════════════════
```

Also check the health endpoint:

```bash
curl http://localhost:8000/api/health
```

```json
{
  "status": "ok",
  "llm_provider": "ollama",
  "threat_intel_enabled": true,
  "demo_mode": false
}
```

In the report UI, the `demo_mode` badge on the Threat Intelligence section will disappear when real APIs are active.

---

## Troubleshooting

### VirusTotal returns 404

Your file hash was not previously submitted to VT. VirusTotal only has data for files it has seen before. For new/private samples, submit the file to VT first via the web UI, then re-analyze.

### Ollama times out

The default request timeout is 120 seconds. On slow machines, increase it in `agents/rag_intelligence.py`:

```python
async with httpx.AsyncClient(timeout=300) as client:
```

### CAPA takes too long

CAPA analysis can take 30–120 seconds on large binaries. This is expected — it's running hundreds of rules. The WebSocket will show the pipeline waiting at "Capability Detection."

### angr install fails on macOS

```bash
# Try with conda instead
conda install -c angr angr

# Or use rizin only (much simpler)
brew install rizin
```

### OpenAI API key not working

```bash
# Test directly
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY" | head -5
```
