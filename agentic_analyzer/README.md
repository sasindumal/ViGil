# 🛡️ ViGiL — Agentic CPG Malware Intelligence Dashboard

An advanced, research-grade static malware analysis and classification system. It leverages Code Property Graphs (CPGs) generated via the core UIR pipeline and segment them into semantic blocks. These blocks are then scrutinized by **15 specialized CrewAI LLM agents** to output verified threat verdicts mapping tactics to MITRE ATT&CK techniques with rigorous trace evidence to eliminate hallucinations.

## Key Features

- **15 Specialized Threat Agents**: Real-time collaborative threat analysis covering AST pattern recognition, variable taint/data-flow tracking, memory injections, virtual debugger checks, persistence registries, cryptographic routines, privilege elevations, network endpoints, and compiler packing mechanisms.
- **Strict Hallucination Audits**: Includes an `Evidence Verification` specialist that inspects and maps every threat assertion back to literal CPG node identifiers (`node_id` calls, API imports, strings) for bulletproof accuracy.
- **Deep Graph Chunking**: Automatically fragments massive CPG JSON graphs (which easily hit 10MB+) into self-contained method/block structures to bypass context window constraints.
- **Sleek Cyber-Dashboard UI**: modern single-page HTML/CSS/JS frontend featuring glowing progress steppers, scrolling terminal console logs of agent thoughts, specialist focus graphs, and accordion report grids.
- **Dynamic Local Provider Support**: Configure OpenAI, local Ollama models, or LM Studio endpoints directly in the `.env` settings.
- **Full Persistent Run Database**: Automatically saves step-by-step thoughts, inputs, outputs, and the ultimate markdown briefs under scoped directories for regression testing and debugging.

## Getting Started

### 1. Configure the LLM Engine

Edit `agentic_analyzer/.env` and choose your provider:

#### Option A: OpenAI (Default)
Set `LLM_PROVIDER=openai` and paste your key in `OPENAI_API_KEY`.

#### Option B: Local Ollama
Set `LLM_PROVIDER=ollama`. Ensure your Ollama server is running locally (default: `http://localhost:11434`), and that you have pulled the model (e.g., `ollama pull llama3`).

#### Option C: LM Studio
Set `LLM_PROVIDER=lmstudio` and verify your local port matches `http://localhost:1234/v1`.

### 2. Launch the Application

Run the helper script from the workspace directory:

```bash
./agentic_analyzer/run.sh
```

This script will verify your Python libraries, install missing elements, and start the FastAPI uvicorn daemon on **http://localhost:8000**.

### 3. Analyze a Sample

1. Navigate to `http://localhost:8000` in your web browser.
2. Drag and drop any binary, script, document, or ZIP container into the dropzone (you can select one of the cached graphs under `cpg/Benignes/` or `cpg/malware/` for immediate pipeline triggers).
3. Watch the pipeline build the CPG, chunk it, and stream the agent thoughts live inside the dashboard terminal.
4. Download or inspect the detailed verified threat brief at the bottom!
