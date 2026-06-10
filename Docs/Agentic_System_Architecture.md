# ViGil Agentic Threat Forensics System — Architecture & Operations Manual

This document provides a comprehensive architecture overview and operational reference for the **ViGil Agentic Threat Forensics & Analysis System**. It details the multi-tiered system design, real-time WebSocket event pipelines, CrewAI security agent consensus swarm, database models, and the Next.js dark glassmorphism dashboard UI.

---

## 1. System Architecture Overview

The ViGil Agentic System is built on a decoupled, multi-tiered architecture that bridges deep-learning binary feature extraction with LLM-powered security agent reasoning:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Next.js Frontend Client                         │
│   - Glassmorphic Dashboard UI        - WhatsApp-Style Interactive Chat │
│   - Custom Markdown Report Render    - Animated SVG Favicon / Branding │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTP API / WebSockets
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      FastAPI Backend Service                           │
│   - ASGI Web Server (Uvicorn)        - WebSocket Event Bus             │
│   - Orchestrator Pipeline Router     - SQLite Database Persistence     │
└──────┬──────────────────────────────────────────────────────────┬──────┘
       │                                                          │
       ▼                                                          ▼
┌────────────────────────────────┐              ┌────────────────────────┐
│    Joint PyTorch ML Model      │              │   CrewAI Agent Swarm   │
│  - Grayscale Byte CNN          │              │  - 5 Parallel Analysts │
│  - Code Property Graph HGT     │              │  - 1 Script Specialist │
│  - RansomFormer Bytes/APIs     │              │  - Consensus Resolvers │
└────────────────────────────────┘              └────────────────────────┘
```

The system components are distributed as follows:
- **Frontend App**: Next.js 15, React 19, tailwind/CSS, custom SVG assets, deployed inside `Agentic_System/frontend/`.
- **Backend Service**: FastAPI, SQLite3, Uvicorn, CrewAI framework, deployed inside `Agentic_System/backend/`.
- **Deep Learning Subsystem**: Standalone PyTorch execution pipeline wrapping the Quad-Modal `JointMalwareModel`, integrated into the backend as a lazy-loaded predictor singleton.

---

## 2. Backend Architecture & Core Components

The backend codebase is structured inside `Agentic_System/backend/` and coordinates file ingestion, routing, execution, and reporting.

### A. API Layer & Entry Point
- **`backend/main.py`**: Configures the FastAPI app instance, CORS middleware mappings, Static files mount point (serving the `uploads/` directory), and WebSocket router connections.
- **Routes Layer (`backend/routes/`)**:
  - `analysis.py`: Handles file upload routing, analysis execution trigger, analysis status queries, database history lists, and deletion tasks.
  - `reports.py`: Serves reports in raw Markdown, parses and exposes reports for download, and generates formatted HTML.
  - `settings.py`: Configures active LLM provider (OpenAI, Gemini, OpenRouter, Ollama, LM Studio, NVIDIA NIM), loads environment parameters, and triggers API connection health checks.
  - `websocket.py`: Manages real-time client WebSocket rooms mapped to analysis sessions (`/ws/analysis/{id}`) and global broadcast listeners (`/ws/global`).

### B. Core Pipeline Orchestrator
- **`backend/core/orchestrator.py` (`Orchestrator`)**: Implements the state machine for processing payloads. The execution sequence is:
  1. **Initialization**: Registers the analysis session ID and checks long-term memory for pre-computed file hashes to support instant caching.
  2. **Routing**: Identifies the uploaded file category (PE executable, Script, or Container archive).
  3. **Recursive Extraction**: If a container is uploaded (e.g. `.zip`, `.msi`), unpacks leaf files, routes them, and performs parallel analysis sub-runs.
  4. **ML Inference**: Invokes the `ModelPredictor` (PyTorch model) to compute the neural network verdict and MC dropout confidence.
  5. **Agent Forensics**: Triggers the CrewAI agent crews (PE Crew or Script Crew) based on the file route.
  6. **Synthesis**: Aggregates the ML prediction values and agent markdown results, resolves the final verdict/risk score, and writes findings into the SQLite database.
  7. **Broadcast**: Emits the final `report_ready` payload via the event emitter.

### C. Live Event Bus
- **`backend/core/event_emitter.py` (`EventEmitter`)**: Orchestrates asynchronous event emissions via WebSocket connection pools. It serializes status payloads using unified classes:
  - `emit_step(...)`: Updates progress bar values (`initialization`, `routing`, `extraction`, `ml_prediction`, `agents_analysis`, `consensus`).
  - `emit_agent(...)`: Broadcasts agent-level thread states (`AGENT_STARTED`, `AGENT_COMPLETED`) to push active agent thoughts to the UI.

### D. Memory & Database Schema
- **`backend/memory/long_term.py` (`LongTermMemory`)**: Manages the persistent SQLite database stored at `data/vigil_memory.db`.
  - **`analyses` table**: Stores analysis session parameters:
    ```sql
    CREATE TABLE IF NOT EXISTS analyses (
        id TEXT PRIMARY KEY,
        file_hash TEXT,
        file_name TEXT,
        file_type TEXT,
        verdict TEXT,
        confidence REAL,
        risk_score REAL,
        full_results_json TEXT,
        report_markdown TEXT,
        created_at TEXT
    );
    ```
  - **`iocs` table**: Stores extracted indicators of compromise linked to analysis sessions:
    ```sql
    CREATE TABLE IF NOT EXISTS iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id TEXT,
        ioc_type TEXT,
        value TEXT,
        context TEXT,
        created_at TEXT,
        FOREIGN KEY(analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
    );
    ```

---

## 3. CrewAI Swarm & Consensus Architecture

The Multi-Agent forensics engine is powered by the CrewAI framework, organized into specialized crews.

### A. PE Analysis Crew (`pe_crew.py`)
Executes an 8-agent swarm to analyze Portable Executable binaries:

```
   ┌────────────────────────────────────────────────────────┐
   │                  5 Parallel Analysts                   │
   │ - Structural Analyst       - API Import Analyst        │
   │ - Network Intel Analyst    - Evasion Specialist        │
   │ - String NLP Analyst                                   │
   └──────┬──────────┬───────────┬───────────┬──────────┬───┘
          │          │           │           │          │
          ▼          ▼           ▼           ▼          ▼
   ┌────────────────────────────────────────────────────────┐
   │              Results Analysis Coordinator              │
   │   - Compiles parallel findings into unified summary    │
   └────────────────────────────┬───────────────────────────┘
                                ▼
   ┌────────────────────────────────────────────────────────┐
   │               ML Model & Agent Consensus               │
   │   - Resolves ML predictions vs. agent-based reasoning   │
   └────────────────────────────┬───────────────────────────┘
                                ▼
   ┌────────────────────────────────────────────────────────┐
   │          Senior Threat Intelligence Reporter           │
   │   - Writes final Markdown report with warning alerts   │
   └────────────────────────────────────────────────────────┘
```

1. **Parallel Stream**: The first 5 agents run concurrently (`async_execution=True`) using isolated task context blocks.
2. **Consolidation**: The `Results Analysis Coordinator` synthesizes parallel outputs, flagging any contradictions (e.g. high entropy but no packer signatures).
3. **Consensus Resolution**: The `Model Consensus Analyst` acts as a judge, weighing the PyTorch ML confidence metrics against the coordinator's findings to output the final verdict.
4. **Report Generation**: The `Senior Threat Intelligence Report Writer` compiles all summaries and tables into the finalized document.

### B. Script Analysis Crew (`script_crew.py`)
Utilizes a high-performance single-agent pipeline:
- **Agent**: `Universal Script Threat Analyst`.
- **Responsibility**: Inspects PowerShell, JavaScript, VBScript, Python, HTA, or Batch code. Performs base64 deobfuscation, LOLBin abuse checks, credential theft pattern matching, C2 extraction, and maps behaviors to MITRE ATT&CK techniques.

### C. Stateless Async Callbacks
To prevent blocking the asynchronous FastAPI event loop during multi-threaded CrewAI executions, the crews run tasks inside `asyncio.get_event_loop().run_in_executor(...)`. 
Individual tasks use a custom thread-safe callback bridge:
```python
def make_callback(agent_role: str, next_agent_role: Optional[str] = None):
    def task_callback(task_output):
        asyncio.run_coroutine_threadsafe(
            event_emitter.emit_agent(
                analysis_id=analysis_id,
                agent_name=agent_role,
                event_type=EventType.AGENT_COMPLETED,
                data={"output": task_output.raw}
            ),
            loop
        )
```
This streams completions live to the frontend. To optimize token costs and speed up executions, agent-level unified RAG memory modules are deactivated (`memory=False`).

---

## 4. Frontend UI/UX Architecture

The frontend is a Next.js 15 application utilizing React 19, styled using modern glassmorphism principles (saturated dark backgrounds, high blur values, thin semi-transparent borders, and neon indicators).

### A. Core Page Routes
- **`/` (Dashboard - `src/app/page.js`)**: Serves as the landing hub. Displays a split hero header with a glass-card enclosing the large pulsing SVG symbol, the file drag-and-drop zone (`FileUpload.jsx`), engine status metrics (ML model load state, active provider, backend latency), and a table of recently processed files.
- **`/settings` (`src/app/settings/page.js`)**: Exposes controls to switch between the 6 LLM providers, input API key values, test model connections, and adjust general system parameters.
- **`/analysis/[id]` (`src/app/analysis/[id]/page.js`)**: Displays the active analysis session using the interactive chat or the multi-tab forensic viewer.

### B. Interactive Chat Stepper (`AgentsChat.jsx`)
Visualizes the forensic analysis pipeline using a WhatsApp-style live group chat:
- **Stage 1-5**: The user's uploaded file name and size appear on the right. Status markers display backend steps (`Initializing database...`, `Routing...`, etc.).
- **Stage 6**: Renders the PyTorch model prediction result with a custom progress spinner.
- **Stage 7**: Streams the security agents' progress. An overlapping stack of agent avatars with custom role colors renders when multiple parallel analysts are running, accompanied by a dynamic status text (e.g. *"Evasion Specialist, String Analyst and 3 other agents are analyzing"*).
- **Stage 8**: Displays the final Orchestrator wrap-up compilation message, then fades into the main tabs dashboard.

### C. Forensic Viewer Tab Layout
Once complete, the dashboard exposes four tabs:
1. **Overview**: Shows overall file metadata, the circular risk gauge, and threat levels.
2. **Deep Static Details**: Displays section-level Shannon entropy bar charts, PE headers, imports classifications, and parsed exports.
3. **Agent Findings**: Shows a message history containing the final summaries submitted by every agent, expandable to reveal full technical outputs.
4. **Threat Report**: Renders the complete formatted Markdown threat intelligence report (`ReportViewer.jsx`).

---

## 5. Modern Threat Report Specification

Threat reports generated by the report writer agent are structured using a premium, standardized Markdown format parsed dynamically by `ReportViewer.jsx`:

1. **Branding Header**:
   ```markdown
   # THREAT INTELLIGENCE & FORENSICS REPORT
   ```
2. **Authoritative Verdict Callout**: Displays the final consensus verdict, confidence, and ViGil Threat Matrix Score in large H1 and H2 headers before the details:
   ```markdown
   # VERDICT: MALWARE
   ## CONFIDENCE: 88% | VIGIL THREAT MATRIX SCORE: 75/100
   ---
   ```
3. **Executive Summary Alert Panel**: Renders inside a glassmorphic warning or caution blockquote:
   ```markdown
   ## 1. Executive Summary
   > [!CAUTION]
   > Critical threat signatures detected. The binary contains obfuscated strings...
   ```
4. **File Metadata Table**: Uses Markdown tables for clean alignment:
   ```markdown
   ## 2. File Metadata & Overview
   | Property | Value |
   | --- | --- |
   | File Name | payload.exe |
   | SHA256 Hash | 0a6c17dc3e... |
   ```
5. **Consensus Logic**: Explains ML model inferences and agent agreements.
6. **Technical Analysis**: Static findings, packers detected, and evasion APIs.
7. **C2 & Network IOCs Table**: Maps IP/Domains with reputation ratings.
8. **MITRE ATT&CK Mapping Table**:
   ```markdown
   ## 5. MITRE ATT&CK Mapping
   | Tactic | Technique ID | Technique Name | Evidence / Abuse Details |
   | --- | --- | --- | --- |
   | Defense Evasion | T1027 | Obfuscated Files | Base64-encoded payload string |
   ```
9. **Mitigation Checklists**: Actionable security recommendations.

---

## 6. Operational Guides

### starting the Backend Server
```bash
cd Agentic_System
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

### starting the Frontend App (Dev Mode)
```bash
cd Agentic_System/frontend
npm run dev
```

### Compiling Frontend Production Bundle
```bash
cd Agentic_System/frontend
npm run build
```
