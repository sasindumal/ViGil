# ViGiL — System Architecture

## Pipeline Overview

```
                         EXE File Upload
                               │
                    ┌──────────▼──────────┐
                    │  Sample Intake Agent │  Agent 1
                    └──────────┬──────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
 ┌────────────────┐  ┌─────────────────┐  ┌──────────────────┐
 │ Static Analysis│  │ Unpacking Agent  │  │ Threat Intel Agent│  Agents 2,3,10
 └────────┬───────┘  └────────┬────────┘  └──────────┬───────┘
          │                   │                       │
          ▼                   ▼                       │
 ┌────────────────┐  ┌─────────────────┐             │
 │Capability Agent│  │ CFG Extraction  │             │  Agents 4,5
 └────────┬───────┘  └────────┬────────┘             │
          │                   │                       │
          └───────────┬────────┘───────────────────────┘
                      ▼
            ┌──────────────────┐
            │ Evasion Detection │  Agent 6
            └──────────┬───────┘
                       ▼
            ┌──────────────────┐
            │Emulation Analysis│  Agent 7
            └──────────┬───────┘
                       ▼
            ┌──────────────────┐
            │ Similarity Agent │  Agent 8
            └──────────┬───────┘
                       ▼
            ┌──────────────────┐
            │Family Clustering  │  Agent 9
            └──────────┬───────┘
                       ▼
            ┌──────────────────┐
            │MITRE ATT&CK Mapping│ Agent 11
            └──────────┬───────┘
                       ▼
            ┌──────────────────┐
            │ RAG Intelligence  │  Agent 12
            └──────────┬───────┘
                       ▼
            ┌──────────────────┐
            │LLM Decompilation  │  Agent 13
            └──────────┬───────┘
                       ▼
            ┌──────────────────┐
            │ YARA Generation   │  Agent 14
            └──────────┬───────┘
                       ▼
            ┌──────────────────┐
            │ATT&CK Navigator   │  Agent 15
            └──────────┬───────┘
                       ▼
            ┌──────────────────┐
            │   STIX Export    │  Agent 16
            └──────────┬───────┘
                       ▼
            ┌──────────────────┐
            │Report Generation  │  Agent 17
            └──────────┬───────┘
                       ▼
     PDF / HTML / JSON / STIX / YARA / ATT&CK Layer
```

## Component Architecture

```
ViGiL/
│
├── backend/                    Python / FastAPI
│   ├── main.py                 REST API + WebSocket server
│   ├── crew.py                 Pipeline orchestrator
│   ├── config.py               Pydantic settings
│   ├── models.py               Data schemas (all agent outputs)
│   └── agents/                 17 agent modules
│
├── frontend/                   React / Vite
│   └── src/
│       ├── pages/
│       │   ├── Landing.jsx     Hero + upload zone
│       │   ├── Analysis.jsx    Real-time pipeline view
│       │   └── Report.jsx      Full forensic report
│       ├── api.js              Backend client
│       └── index.css           Design system
│
└── docs/                       Documentation
```

## Data Flow

1. **Upload**: User drops a PE file on the Landing page
2. **Job Creation**: FastAPI creates a job record and stores the file
3. **Pipeline Start**: `crew.py` runs all 17 agents sequentially
4. **WebSocket**: Each agent broadcasts progress events in real time
5. **Frontend**: Analysis page shows live pipeline status and logs
6. **Report**: When complete, user is redirected to the full forensic report
7. **Downloads**: PDF, JSON, STIX, YARA, ATT&CK Layer available for download

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
