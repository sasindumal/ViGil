# ViGiL — System Architecture
## Pipeline Overview (ViGiL v2.0)

```
                         EXE File Upload
                                │
               ┌────────────────┴────────────────┐
               │    Phase 1: Deterministic Tools │
               └────────────────┬────────────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          ▼                     ▼                     ▼
 ┌────────────────┐    ┌─────────────────┐   ┌──────────────────┐
 │ Static Analysis│    │ Unpacking Agent │   │ Threat Intel     │
 └────────┬───────┘    └────────┬────────┘   └──────────┬───────┘
          │                     │                       │
          ▼                     ▼                       ▼
 ┌────────────────┐    ┌─────────────────┐   ┌──────────────────┐
 │ Capabilities   │    │ CFG Extraction  │   │ Evasion Detection│
 └────────┬───────┘    └────────┬────────┘   └──────────┬───────┘
          │                     │                       │
          ▼                     ▼                       ▼
 ┌────────────────┐    ┌─────────────────┐   ┌──────────────────┐
 │ Emulation      │    │ Similarity Agent│   │ Family Clustering│
 └────────┬───────┘    └────────┬────────┘   └──────────┬───────┘
          └─────────────────────┼───────────────────────┘
                                │
               ┌────────────────┴────────────────┐
               │  Phase 2: CrewAI Agentic AI     │
               │ (Hierarchical Reasoning Engine) │
               └────────────────┬────────────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          ▼                     ▼                     ▼
 ┌────────────────┐    ┌─────────────────┐   ┌──────────────────┐
 │ Static PE AI   │    │ Behavioral AI   │   │ Threat Intel AI  │
 └────────┬───────┘    └────────┬────────┘   └──────────┬───────┘
          └─────────────────────┼───────────────────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          ▼                     ▼                     ▼
 ┌────────────────┐    ┌─────────────────┐   ┌──────────────────┐
 │ Verdict Analyst│    │ Report Writer   │   │ Fallback Scripts │
 └────────┬───────┘    └────────┬────────┘   └──────────┬───────┘
          └─────────────────────┼───────────────────────┘
                                │
               ┌────────────────┴────────────────┐
               │    Phase 3: Final Assembly      │
               └────────────────┬────────────────┘
                                │
                     PDF / HTML / JSON / STIX
```

## Component Architecture

```
ViGiL/
│
├── backend/                    Python / FastAPI
│   ├── main.py                 REST API + WebSocket server
│   ├── crew.py                 Pipeline orchestrator (Phase 1 & 3)
│   ├── vigil_crew.py           CrewAI agentic reasoning (Phase 2)
│   ├── db.py                   SQLite persistence layer
│   ├── config.py               Pydantic settings
│   ├── models.py               Data schemas (all agent outputs)
│   └── agents/                 Deterministic tool wrappers
│
├── frontend/                   React / Vite
│   └── src/
│       ├── pages/
│       │   ├── Landing.jsx     Hero + upload zone
│       │   ├── Analysis.jsx    Real-time pipeline view (Phases 1-3)
│       │   └── Report.jsx      Full forensic report + AI Verdict
│       ├── api.js              Backend client
│       └── index.css           Design system
│
└── docs/                       Documentation
```

## Data Flow

1. **Upload**: User drops a PE file on the Landing page
2. **Job Creation**: FastAPI creates a job record in SQLite and stores the file
3. **Phase 1 (Tools)**: `crew.py` runs all deterministic tools in parallel using `asyncio.gather`
4. **Phase 2 (CrewAI)**: `vigil_crew.py` instantiates 5 specialized LLM agents managed by a Hierarchical Manager to synthesize the evidence.
5. **WebSocket**: Each tool and AI agent broadcasts progress events in real time.
6. **Frontend**: Analysis page shows live pipeline status, logging, and agentic AI thinking.
7. **Report**: Final verdict is rendered (AI verdict takes precedence), and artifacts are available for download.

## Verdict Computation

The final threat verdict is now primarily driven by the **CrewAI Verdict Analyst**. The deterministic tools provide the evidence (Threat Intel, CAPA, Evasion, etc.), and the AI synthesizes it into a JSON verdict containing:
- Threat Level (malicious/suspicious/clean)
- Confidence Score (0.0 to 1.0)
- Malware Family
- Executive Summary & Recommended Actions

*If CrewAI is disabled or fails, the system falls back to a deterministic weighted computation.*

## Verdict Computation

The final threat verdict is computed by `agents/report_generation.py` using weighted evidence:

| Evidence Source | Weight |
|----------------|--------|
| Threat Intelligence (VT + MBZ) | 30% |
| Capability Detection (CAPA) | 25% |
| Evasion Techniques | 20% |
| Family Similarity | 15% |
| Packing / High Entropy | 10% |

**Thresholds:**
- ≥ 75% → **MALICIOUS**
- 40-74% → **SUSPICIOUS**
- < 10% → **CLEAN**

## Fallback Strategy

Every agent implements graceful fallbacks when optional tools are not installed:

| Tool | Fallback |
|------|---------|
| CAPA | Import table heuristic analysis |
| FLOSS | Python ASCII string extraction |
| Speakeasy | Static import → behavior inference |
| angr | rizin → empty CFG |
| VirusTotal/MBZ | Realistic mock responses |
| LLM | Pre-written static summaries |
