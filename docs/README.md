# ViGiL — Multi-Agent Malware Analysis Platform

> **Demo mode is on by default** — no API keys or tools required to run the platform. See [real-mode.md](./real-mode.md) to switch any layer to real data.

<div align="center">

```
██╗   ██╗██╗ ██████╗ ██╗██╗
██║   ██║██║██╔════╝ ██║██║
██║   ██║██║██║  ███╗██║██║
╚██╗ ██╔╝██║██║   ██║██║██║
 ╚████╔╝ ██║╚██████╔╝██║███████╗
  ╚═══╝  ╚═╝ ╚═════╝ ╚═╝╚══════╝
```

**Evidence-Based Malware Analysis — Not ML Black Boxes**

</div>

---

## Overview

ViGiL is an analyst-focused malware triage and reverse-engineering platform. Instead of an ML model predicting "malicious/benign," every verdict is assembled from **14 deterministic tools** passing evidence into a **5-Agent CrewAI Hierarchical Engine**.

The verdict is produced from:
- **Static evidence** — PE sections, imports, entropy, strings
- **Emulation evidence** — behavioral trace without real execution
- **Evasion indicators** — anti-VM, anti-debug, API obfuscation
- **CAPA capabilities** — credential theft, injection, ransomware
- **Threat intelligence** — VirusTotal, MalwareBazaar, AbuseIPDB, OTX
- **CrewAI Synthesis** — 5 LLM agents acting as Static, Behavioral, Threat Intel, and Verdict analysts
- **ATT&CK technique coverage** — mapped with confidence scores

Every conclusion is traceable to specific, concrete evidence via the AI reasoning chain.

---

## Quick Start

### Prerequisites

| Tool | Version | Required? |
|------|---------|-----------|
| Python | ≥ 3.11 | Yes |
| Node.js | ≥ 18 | Yes |
| npm | ≥ 9 | Yes |
| pefile | via pip | Yes |
| CAPA | binary | Optional (graceful fallback) |
| FLOSS | binary | Optional (graceful fallback) |
| Speakeasy | via pip | Optional (graceful fallback) |
| angr | via pip | Optional (graceful fallback) |
| UPX | binary | Optional |
| rizin | binary | Optional |

### 1. Clone & Configure

```bash
git clone https://github.com/your-org/ViGiL.git
cd ViGiL
cp .env.example .env
# Edit .env with your API keys and LLM provider
```

### 2. Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Start Backend

```bash
cd backend
python main.py
# API available at http://localhost:8000
# Swagger docs at http://localhost:8000/api/docs
```

### 4. Frontend Setup

```bash
cd frontend
npm install
npm run dev
# App available at http://localhost:5173
```

---

## Configuration

All settings live in `.env` (copy from `.env.example`):

```env
# Agentic AI
CREWAI_ENABLED=true
CREWAI_VERBOSE=true

# LLM Provider: openai | gemini | ollama | lmstudio
LLM_PROVIDER=openai
OPENAI_API_KEY=your_key_here

# Threat Intelligence (optional — demo mode if empty)
VIRUSTOTAL_API_KEY=
MALWAREBAZAAR_API_KEY=

# Vector Store: faiss (default) | qdrant
VECTOR_STORE=faiss
```

> **Demo Mode**: If threat intel API keys are not set, the system uses realistic mock responses. All other agents run fully with real analysis.

---

## Documentation

| Guide | Description |
|-------|------------|
| [architecture.md](./architecture.md) | Pipeline diagram and data flow |
| [agents.md](./agents.md) | All 17 agents documented |
| [api.md](./api.md) | REST API and WebSocket reference |
| [setup.md](./setup.md) | Step-by-step installation guide |
| [tech_stack.md](./tech_stack.md) | Technology choices and rationale |
| [real-mode.md](./real-mode.md) | **How to switch from mock to real data** |
| [platforms.md](./platforms.md) | macOS and Linux compatibility guide |

## Setup Scripts

One-command tool installation (optional analysis tools only — core platform runs without them):

```bash
# macOS (Apple Silicon or Intel — auto-detected)
bash scripts/setup-macos.sh

# Linux (Ubuntu/Debian/Fedora/Arch — auto-detected)
bash scripts/setup-linux.sh

# Verify all tools after setup
bash scripts/check-tools.sh
```


---

## Generated Artifacts

For each analysis, ViGiL produces:

| Artifact | Format | Description |
|----------|--------|-------------|
| `report.json` | JSON | Full structured report |
| `report.pdf` | PDF | Client-side export |
| `report.stix.json` | STIX 2.1 | OpenCTI/MISP/TAXII compatible |
| `generated.yara` | YARA | Auto-generated hunting rules |
| `attack_layer.json` | ATT&CK Navigator | Import into MITRE Navigator |
| `cfg.json` | JSON | Control flow graph |
| `callgraph.json` | JSON | API call graph |

---

## License

MIT License. See LICENSE file.
