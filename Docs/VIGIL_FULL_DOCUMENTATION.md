# ViGil — Full System Documentation

> **Version:** 1.0.0 · **Architecture:** Quad-Modal ML + Multi-Agent Agentic System · **Stack:** PyTorch · FastAPI · CrewAI · Next.js

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [High-Level Architecture](#2-high-level-architecture)
3. [Repository Structure](#3-repository-structure)
4. [UIR — Unified Instruction Representation Library](#4-uir--unified-instruction-representation-library)
   - 4.1 [File Identification & Type System](#41-file-identification--type-system)
   - 4.2 [Recursive Archive Extractor](#42-recursive-archive-extractor)
   - 4.3 [Code Lifters](#43-code-lifters)
   - 4.4 [Code Property Graph (CPG)](#44-code-property-graph-cpg)
   - 4.5 [Tokenization](#45-tokenization)
   - 4.6 [Feature Extraction Pipeline](#46-feature-extraction-pipeline)
   - 4.7 [Batch Processor & CLI](#47-batch-processor--cli)
5. [ML Model — Quad-Modal JointMalwareModel](#5-ml-model--quad-modal-jointmalwaremodel)
   - 5.1 [Model Overview & Hyperparameters](#51-model-overview--hyperparameters)
   - 5.2 [Stream 1: OptimizedHGT (CPG Graph Encoder)](#52-stream-1-optimizedhgt-cpg-graph-encoder)
   - 5.3 [Stream 2: OptimizedCNN (Grayscale Image Encoder)](#53-stream-2-optimizedcnn-grayscale-image-encoder)
   - 5.4 [Stream 3: OptimizedByteEncoder (PE Bytes Encoder)](#54-stream-3-optimizedbyteencoder-pe-bytes-encoder)
   - 5.5 [Stream 4: OptimizedAPIEncoder (API Import Encoder)](#55-stream-4-optimizedapiencoder-api-import-encoder)
   - 5.6 [Cross-Modal Fusion: OptimizedRansomFormerEncoder](#56-cross-modal-fusion-optimizedransomformerencoder)
   - 5.7 [Fusion Head: OptimizedFusion (Deep Residual MLP)](#57-fusion-head-optimizedfusion-deep-residual-mlp)
   - 5.8 [Full Model: JointMalwareModel](#58-full-model-jointmalwaremodel)
   - 5.9 [Monte Carlo Dropout Inference](#59-monte-carlo-dropout-inference)
6. [Training Workflow](#6-training-workflow)
   - 6.1 [Step 1: Dataset Collection](#61-step-1-dataset-collection)
   - 6.2 [Step 2: Feature Extraction](#62-step-2-feature-extraction)
   - 6.3 [Step 3: Dataset Classes](#63-step-3-dataset-classes)
   - 6.4 [Step 4: Kaggle GPU Training](#64-step-4-kaggle-gpu-training)
   - 6.5 [Training Configuration & Hyperparameters](#65-training-configuration--hyperparameters)
   - 6.6 [Step 5: Model Deployment](#66-step-5-model-deployment)
7. [Agentic System — Backend](#7-agentic-system--backend)
   - 7.1 [FastAPI Entry Point](#71-fastapi-entry-point)
   - 7.2 [Configuration System](#72-configuration-system)
   - 7.3 [Analysis Orchestrator](#73-analysis-orchestrator)
   - 7.4 [File Router](#74-file-router)
   - 7.5 [PE Deep Analyzer (15 Modules)](#75-pe-deep-analyzer-15-modules)
   - 7.6 [ML Model Predictor](#76-ml-model-predictor)
   - 7.7 [AI Agent Crews (CrewAI)](#77-ai-agent-crews-crewai)
   - 7.8 [PE Analysis Crew — 8 Agents](#78-pe-analysis-crew--8-agents)
   - 7.9 [Script Analysis Crew — 1 Agent](#79-script-analysis-crew--1-agent)
   - 7.10 [LLM Configuration Factory](#710-llm-configuration-factory)
   - 7.11 [Memory System](#711-memory-system)
   - 7.12 [Event Emitter (WebSocket SSE)](#712-event-emitter-websocket-sse)
8. [API Reference](#8-api-reference)
   - 8.1 [Analysis Endpoints](#81-analysis-endpoints)
   - 8.2 [Reports Endpoints](#82-reports-endpoints)
   - 8.3 [Settings Endpoints](#83-settings-endpoints)
   - 8.4 [WebSocket Endpoints](#84-websocket-endpoints)
9. [Agentic System — Frontend](#9-agentic-system--frontend)
   - 9.1 [Pages & Routing](#91-pages--routing)
   - 9.2 [Components](#92-components)
10. [Supported File Types](#10-supported-file-types)
11. [Installation & Setup](#11-installation--setup)
12. [Configuration Reference](#12-configuration-reference)
13. [CLI Reference](#13-cli-reference)
14. [Prediction Script](#14-prediction-script)
15. [Dependencies Reference](#15-dependencies-reference)
16. [Security Considerations](#16-security-considerations)

---

## 1. Project Overview

**ViGil** is a production-grade, AI-powered malware analysis and threat classification system. It combines two complementary technologies:

1. **Quad-Modal Deep Learning Model** — A joint neural network (`JointMalwareModel`) that fuses four independent analysis streams (Code Property Graph, Grayscale image, PE byte sequence, and API import tokens) through a Deep Residual MLP to classify files as `BENIGN` or `MALWARE` with confidence and epistemic uncertainty estimates.

2. **Multi-Agent Agentic System** — A CrewAI-powered backend where specialized LLM agents perform deep forensic analysis of PE files and scripts, producing structured MITRE ATT&CK-mapped threat intelligence reports.

**Key Capabilities:**
- Static analysis of PE files, scripts, documents, and archives
- Quad-modal deep learning inference with Monte Carlo Dropout uncertainty
- 8 specialized CrewAI agents for PE forensics running in parallel + sequential phases
- 1 universal agent for script analysis
- Real-time WebSocket event streaming of agent progress to a React frontend
- 4-tier memory system: Long-Term (SQLite), Knowledge Base (JSON), Short-Term (in-memory), Entity Memory (IOC correlation)
- Multi-LLM provider support: OpenAI, Google Gemini, Ollama, NVIDIA NIM, OpenRouter, LM Studio

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          ViGil Full System                               │
│                                                                          │
│  ┌──────────────┐   REST/WS   ┌───────────────────────────────────────┐ │
│  │  Next.js     │ ◄──────────►│     FastAPI Agentic Backend           │ │
│  │  Frontend    │             │                                       │ │
│  │  (Port 3000) │             │  ┌───────────────────────────────┐   │ │
│  │              │             │  │   Analysis Orchestrator       │   │ │
│  │  • Dashboard │             │  │   orchestrator.py             │   │ │
│  │  • Upload    │             │  └──────────┬────────────────────┘   │ │
│  │  • Analysis  │             │             │                         │ │
│  │  • Reports   │             │  ┌──────────▼──────────────────────┐ │ │
│  │  • Settings  │             │  │   File Router                   │ │ │
│  └──────────────┘             │  │   PE → Script → Container       │ │ │
│                               │  └──────┬────────┬────────┬────────┘ │ │
│                               │         │        │        │           │ │
│                               │  ┌──────▼──┐ ┌──▼───┐ ┌─▼────────┐ │ │
│                               │  │ PE Deep │ │Script│ │Recursive │ │ │
│                               │  │Analyzer │ │Crew  │ │Extractor │ │ │
│                               │  │(15 mods)│ │(1ag) │ │          │ │ │
│                               │  └──────┬──┘ └──────┘ └──────────┘ │ │
│                               │         │                            │ │
│                               │  ┌──────▼──────────────────────────┐ │ │
│                               │  │   ML Model Predictor            │ │ │
│                               │  │   JointMalwareModel (PyTorch)   │ │ │
│                               │  └──────┬──────────────────────────┘ │ │
│                               │         │                            │ │
│                               │  ┌──────▼──────────────────────────┐ │ │
│                               │  │   PE Analysis Crew (8 agents)   │ │ │
│                               │  │   Phase 1: 5 parallel agents    │ │ │
│                               │  │   Phase 2: 3 sequential agents  │ │ │
│                               │  └─────────────────────────────────┘ │ │
│                               │                                       │ │
│                               │  ┌─────────────────────────────────┐ │ │
│                               │  │   Memory & Persistence          │ │ │
│                               │  │   SQLite · JSON KB · IOC Store  │ │ │
│                               │  └─────────────────────────────────┘ │ │
│                               └───────────────────────────────────────┘ │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    UIR Library (Python Package)                  │   │
│  │  extraction · lifting · cpg · tokenization · model · pipeline   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Repository Structure

```
ViGil/
├── README.md                        ← Quick-start guide
├── predict.py                       ← Standalone CLI predictor
├── export_zip.py                    ← Deployment packaging script
├── setup.py                         ← Python package setup (uir)
├── requirements.txt                 ← UIR/ML core dependencies
│
├── uir/                             ← Unified Instruction Representation library
│   ├── config.py                    ← Pydantic configuration for all UIR subsystems
│   ├── extraction/                  ← File identification, archive/image/PE extraction
│   │   ├── file_identifier.py       ← Magic-byte + extension file type detection
│   │   ├── archive_extractor.py     ← ZIP/7z/RAR/TAR/GZ extraction
│   │   ├── disk_image_extractor.py  ← ISO/IMG disk image mounting and extraction
│   │   ├── msi_extractor.py         ← MSI installer extraction
│   │   ├── pe_feature_extractor.py  ← Raw PE byte & API feature extraction
│   │   ├── image_generator.py       ← Byte-to-grayscale image rendering (224×224)
│   │   └── recursive_engine.py      ← Recursive multi-layer archive unpacker
│   ├── lifting/                     ← Binary/script/document → intermediate representation
│   │   ├── base_lifter.py           ← Abstract base lifter interface
│   │   ├── binary_lifter.py         ← PE/ELF/Mach-O disassembly + function extraction
│   │   ├── script_lifter.py         ← AST generation for JS/PS1/PY/BAT scripts
│   │   ├── document_lifter.py       ← Office OLE/PDF embedded code extraction
│   │   └── launcher_lifter.py       ← LNK/URL/DESKTOP shortcut analysis
│   ├── cpg/                         ← Code Property Graph construction
│   │   ├── schema.py                ← Node types, edge types, CPG schema definitions
│   │   ├── builder.py               ← Converts lifted IR to heterogeneous CPG
│   │   └── graph.py                 ← CPG graph operations and serialization
│   ├── tokenization/                ← Vocabulary, BPE tokenization, embeddings
│   ├── model/                       ← Neural network model classes
│   │   ├── optimized_models.py      ← Primary model file (use this for training/inference)
│   │   ├── dataset.py               ← CPGDataset, PreExtractedDataset, .feat.pt loading
│   │   ├── hgt.py                   ← HGT model library support
│   │   ├── joint_model.py           ← Joint model variant
│   │   ├── joint_trainer.py         ← Training loop for joint model
│   │   ├── trainer.py               ← General-purpose trainer
│   │   ├── evaluator.py             ← Evaluation metrics and confusion matrix
│   │   ├── ensemble.py              ← Ensemble model support
│   │   ├── ransomformer.py          ← RansomFormer dual-stream encoder reference
│   │   └── resnet_extractor.py      ← ResNet image feature extractor (alternative)
│   └── pipeline/                    ← End-to-end processing pipeline
│       ├── processor.py             ← Single file processor
│       ├── batch_processor.py       ← Multi-file parallel batch processor
│       ├── accelerator.py           ← Hardware-profile-aware acceleration
│       └── cli.py                   ← CLI entry point (`uir` command)
│
├── traning_notebook/
│   └── vigil.ipynb                  ← Kaggle GPU training notebook (primary)
│
├── models/
│   └── 01/
│       ├── models/
│       │   └── joint_model.pt       ← Trained model checkpoint (~158 MB)
│       ├── model_config.json        ← Architecture hyperparameters
│       ├── confusion_matrix.png     ← Training evaluation results
│       └── README.md
│
├── Agentic_System/                  ← Full-stack agentic application
│   ├── .env / .env.example          ← Environment variables
│   ├── requirements.txt             ← Agentic system dependencies
│   ├── backend/                     ← FastAPI Python backend
│   │   ├── main.py                  ← FastAPI app, lifespan, CORS, routers
│   │   ├── config.py                ← Pydantic settings (LLM, storage, server)
│   │   ├── core/
│   │   │   ├── orchestrator.py      ← Master analysis orchestrator (9-step pipeline)
│   │   │   ├── file_router.py       ← File type → analysis route mapping
│   │   │   └── event_emitter.py     ← WebSocket broadcast system (singleton)
│   │   ├── analyzers/               ← 15 PE static analysis modules
│   │   │   ├── pe_deep_analyzer.py  ← Master aggregator (runs all 15 in parallel)
│   │   │   ├── headers.py           ← DOS/NT/Optional PE header parsing
│   │   │   ├── sections.py          ← Section table analysis + anomaly detection
│   │   │   ├── imports_analysis.py  ← DLL imports, suspicious API detection
│   │   │   ├── exports_analysis.py  ← Export directory analysis
│   │   │   ├── strings_extractor.py ← ASCII/Unicode string extraction + IOC parsing
│   │   │   ├── entropy.py           ← Overall + per-section Shannon entropy
│   │   │   ├── cfg_analyzer.py      ← Control Flow Graph properties (Capstone)
│   │   │   ├── api_call_graph.py    ← API call relationship graph
│   │   │   ├── signatures.py        ← YARA signature matching
│   │   │   ├── packer_detector.py   ← Packer/protector identification
│   │   │   ├── debug_features.py    ← Anti-debug/anti-analysis API detection
│   │   │   ├── certificate.py       ← Authenticode certificate parsing (signify)
│   │   │   ├── overlay.py           ← PE overlay data detection
│   │   │   ├── resources.py         ← Resource directory analysis
│   │   │   └── memory_layout.py     ← Virtual memory layout reconstruction
│   │   ├── ml/
│   │   │   └── model_predictor.py   ← Singleton ML inference wrapper
│   │   ├── agents/                  ← CrewAI agent definitions
│   │   │   ├── llm_config.py        ← Multi-provider LLM factory
│   │   │   ├── memory_manager.py    ← CrewAI memory configuration
│   │   │   ├── pe_crew.py           ← PE Analysis Crew (8 agents)
│   │   │   ├── script_crew.py       ← Script Analysis Crew (1 agent)
│   │   │   └── pe_agents/           ← Individual PE agent modules
│   │   │       ├── structural_analyst.py
│   │   │       ├── import_behavior.py
│   │   │       ├── network_intel.py
│   │   │       ├── evasion_specialist.py
│   │   │       ├── string_nlp.py
│   │   │       ├── results_analyzer.py
│   │   │       ├── model_comparator.py
│   │   │       └── report_generator.py
│   │   ├── memory/                  ← 4-tier memory system
│   │   │   ├── long_term.py         ← SQLite async persistence (aiosqlite)
│   │   │   ├── knowledge_base.py    ← JSON file-backed threat intelligence KB
│   │   │   ├── short_term.py        ← In-memory session storage
│   │   │   └── entity_memory.py     ← IOC entity correlation layer
│   │   └── routes/                  ← FastAPI route handlers
│   │       ├── analysis.py          ← Upload, status, history, delete endpoints
│   │       ├── reports.py           ← Report retrieval and download
│   │       ├── settings.py          ← LLM configuration, provider test
│   │       └── websocket.py         ← WebSocket session and global channels
│   └── frontend/                    ← Next.js React dashboard
│       ├── src/app/
│       │   ├── page.js              ← Main dashboard (upload + history + status)
│       │   ├── analysis/            ← Analysis results page
│       │   └── settings/            ← Settings configuration page
│       └── src/components/
│           ├── AgentsChat.jsx       ← Live agent output terminal
│           ├── AgentCard.jsx        ← Individual agent status card
│           ├── FileUpload.jsx       ← Drag-and-drop file uploader
│           ├── ReportViewer.jsx     ← Markdown threat report renderer
│           ├── RiskGauge.jsx        ← Risk score visual gauge
│           ├── EntropyChart.jsx     ← Section entropy visualization
│           ├── SettingsPanel.jsx    ← LLM provider configuration panel
│           ├── Header.jsx           ← Navigation header
│           └── Sidebar.jsx          ← Navigation sidebar
│
├── Docs/                            ← Documentation and architecture diagrams
└── cpg_cache/                       ← CPG build cache (auto-generated)
```

---

## 4. UIR — Unified Instruction Representation Library

The `uir` package is the foundational data extraction library. It converts raw files of any type into structured representations suitable for deep learning training and inference.

### 4.1 File Identification & Type System

**File:** `uir/extraction/file_identifier.py`

`FileIdentifier` uses Python `magic` (libmagic bindings) combined with file extension analysis to identify file types with a confidence score.

**FileType Enum** (defined in `uir/config.py`):

| Category | File Types |
|---|---|
| Native Binary | EXE, DLL, SYS, ELF, MACHO, SO, SCR, CPL |
| Managed Code | JAR, CLASS, APK, DEX |
| Script | JS, VBS, PS1, BAT, CMD, SH, PY, PL, LUA, PHP, HTA, WSF, AU3, JSE, VBE |
| Office/OLE | DOC, DOCX, DOCM, XLS, XLSX, XLSM, XLL, PPT, PPTX, PPAM |
| Rich Documents | PDF, RTF |
| Archives | ZIP, 7Z, RAR, GZ, TAR, ISO, IMG, CAB |
| Installers | MSI, DMG |
| Launchers | LNK, URL, DESKTOP |
| Data/Config | HTML, XML, JSON, INI, VHD |

**FileCategory Enum**: `native_binary`, `managed_code`, `script`, `office_ole`, `rich_doc`, `archive`, `installer`, `launcher`, `data_config`, `unknown`

### 4.2 Recursive Archive Extractor

**File:** `uir/extraction/recursive_engine.py`

`RecursiveExtractor` unpacks multi-level archives recursively up to a configurable depth (default: 5 levels, max 1,000 extracted files). Supports:
- ZIP via Python's `zipfile`
- 7z via `py7zr`
- RAR via `rarfile`
- TAR/GZ via Python's `tarfile`
- ISO/IMG via `pycdlib`
- CAB files
- MSI installers via `uir/extraction/msi_extractor.py`

After extraction, it returns a list of **leaf files** — the deepest-level extracted items with their paths and type metadata.

### 4.3 Code Lifters

**Directory:** `uir/lifting/`

Lifters transform raw binary/script/document files into an intermediate representation that CPG Builder can consume.

| Lifter | Input | Operation |
|---|---|---|
| `BinaryLifter` | PE/ELF/Mach-O | Disassembly via Capstone, function boundary detection, control flow analysis |
| `ScriptLifter` | JS/PS1/PY/BAT/etc. | AST generation via `tree-sitter`, function/call extraction |
| `DocumentLifter` | Office OLE/PDF | Embedded macro/script extraction via `oletools` |
| `LauncherLifter` | LNK/URL | Target path, arguments, icon parsing via `pylnk3` |

All lifters implement the `BaseLifter` abstract interface with a `lift(file_path) → IR` method.

### 4.4 Code Property Graph (CPG)

**Directory:** `uir/cpg/`

The CPG is a heterogeneous directed graph representing code at multiple abstraction levels simultaneously.

**Schema** (`uir/cpg/schema.py`):

| Node Type | Description |
|---|---|
| `FUNCTION` | Detected function/procedure |
| `CALL_SITE` | Function call instruction |
| `DATA_NODE` | Variable/constant/parameter |
| `CONTROL_NODE` | Control flow node (if/loop/ret) |
| `LITERAL` | String/numeric literal |

**Edge Types:**

| Edge Type | Description |
|---|---|
| `AST` | Abstract Syntax Tree parent→child |
| `CFG` | Control flow graph edge |
| `DATA_FLOW` | Data dependency/def-use |
| `CONTROL_DEP` | Control dependency |
| `CALL` | Caller → callee relationship |

**CPGConfig** defaults:
- `include_ast_edges: true`
- `include_cfg_edges: true`
- `include_data_flow_edges: true`
- `include_control_dep_edges: true`
- `max_nodes_per_graph: 50,000`

**CPGBuilder** (`uir/cpg/builder.py`) converts the lifted IR into a CPG object. The CPG is serialized to disk as `.cpg.json` and cached in `cpg_cache/` to avoid recomputation.

### 4.5 Tokenization

**Directory:** `uir/tokenization/`

The tokenization module converts raw string identifiers (API names, function names, constants) into integer token IDs using Byte Pair Encoding (BPE):

| Config | Default |
|---|---|
| `vocab_size` | 32,000 |
| `bpe_vocab_size` | 8,000 |
| `embedding_dim` | 256 |
| `small_int_range` | (-1000, 1000) |

For the `CLSTransformerAPI` encoder, API names are tokenized into `[256]` integer token IDs with vocabulary size 4,096.

### 4.6 Feature Extraction Pipeline

**Files:** `uir/extraction/pe_feature_extractor.py`, `uir/extraction/image_generator.py`

For each PE file, the feature extraction pipeline produces a `.feat.pt` bundle — a PyTorch tensor dict saved to disk — containing:

| Feature | Shape | Description |
|---|---|---|
| `x` | `[N, 320]` | CPG node feature vectors (320-dim) |
| `edge_index` | `[2, E]` | CPG edge connectivity |
| `node_types` | `[N]` | Integer node type IDs (0-63) |
| `edge_types` | `[E]` | Integer edge type IDs (0-63) |
| `batch` | `[N]` | Graph batch index |
| `images` | `[3, 224, 224]` | ImageNet-normalized grayscale image tensor |
| `pe_bytes` | `[1, 1024]` | First 1,024 raw bytes (float32) |
| `api_tokens` | `[256]` | Tokenized API import IDs (int64) |
| `label` | scalar | 0 = BENIGN, 1 = MALWARE |

**Image generation** (`image_generator.py`): Reads raw PE bytes, reshapes them into a 2D array, resizes to `224×224`, converts to 3-channel RGB, and applies ImageNet normalization `(mean=[0.485,0.456,0.406], std=[0.229,0.224,0.225])`.

### 4.7 Batch Processor & CLI

**Files:** `uir/pipeline/batch_processor.py`, `uir/pipeline/cli.py`

`BatchProcessor` processes an entire directory of samples in parallel using hardware-profile-aware worker pools.

**Hardware Profiles** (`HardwareProfile` enum):

| Profile | Description |
|---|---|
| `auto` | Auto-detect from system specs |
| `m4` | Apple M4 — unified memory, memory-mapped I/O optimizations |
| `gtx_1650_ti` | NVIDIA 1650 Ti — 4GB VRAM, batch-size optimized |
| `cpu_default` | Fallback CPU-only processing |

**CLI Entry Point** (`uir` command, registered via `setup.py`):

```bash
uir process --input file.exe --output file.cpg.json --verbose
uir batch --input-dir ./dataset --output-dir ./features --device-profile m4
uir predict --model models/01/models/joint_model.pt --input suspicious.exe
```

---

## 5. ML Model — Quad-Modal JointMalwareModel

**Primary File:** `uir/model/optimized_models.py`

### 5.1 Model Overview & Hyperparameters

The `JointMalwareModel` fuses four independent encoding streams into a single binary classification output.

**Canonical Hyperparameters** (`NOTEBOOK_CFG`):

| Parameter | Value | Description |
|---|---|---|
| `embedding_dim` | 320 | CPG node feature input dimension |
| `hidden_dim` | 384 | HGT hidden state dimension |
| `num_heads` | 8 | Multi-head attention heads |
| `num_layers` | 6 | HGT transformer layers |
| `num_classes` | 2 | BENIGN / MALWARE |
| `fused_dim` | 1536 | HGT(768) + CNN(512) + RF(256) |
| `byte_seq_len` | 1024 | PE byte sequence length |
| `max_apis` | 256 | API import token sequence length |
| `api_vocab_size` | 4096 | API tokenizer vocabulary size |

**Architecture Label:** `OptimizedHGT + ConvNeXt + AttentionByte + CLSTransformerAPI → DeepResMLP`

### 5.2 Stream 1: OptimizedHGT (CPG Graph Encoder)

**Class:** `OptimizedHGT` + `OptimizedHGTLayer`

**Input:** CPG node features `[N, 320]`, edge index `[2, E]`, node types `[N]`, edge types `[E]`, batch `[N]`
**Output:** Graph embedding `[B, 768]`

**Architecture:**
1. **Input Projection:** `Linear(320 → 384) → GELU → LayerNorm → Dropout(0.1)`
2. **6 × OptimizedHGTLayer:**
   - Learned node-type embeddings `Embedding(64, 384)` added to node features
   - Learned edge-type attention bias `Embedding(64, 8)` added to attention scores
   - Multi-head attention (8 heads, d=48 per head) with Q/K/V projections
   - Numerically stable softmax (scatter-based max subtraction, float32)
   - LayerNorm residual with learnable `alpha` scale parameter
3. **JK (Jumping Knowledge) Aggregation:** Learnable weighted sum across all 7 layer outputs (input + 6 layers) via `Softmax(jk_weight)`
4. **Attention Pooling:** Per-node score `Linear(384 → 1)`, softmax over batch, weighted sum
5. **Output Projection:** `Linear(384 → 384) → GELU → LayerNorm → Dropout(0.2) → Linear(384 → 768)`

### 5.3 Stream 2: OptimizedCNN (Grayscale Image Encoder)

**Class:** `OptimizedCNN`

**Input:** `[B, 3, 224, 224]` ImageNet-normalized RGB tensor
**Output:** `[B, 512]`

**Architecture:**
1. **Backbone:** ConvNeXt-Tiny with ImageNet1K_V1 pretrained weights
2. **Pooling:** `AdaptiveAvgPool2d((1, 1))` → flatten `[B, 768]`
3. **Projection:** `Linear(768 → 512) → LayerNorm(512) → GELU → Dropout(0.2)`

### 5.4 Stream 3: OptimizedByteEncoder (PE Bytes Encoder)

**Class:** `OptimizedByteEncoder`

**Input:** `[B, 1, 1024]` float32 byte sequence
**Output:** `[B, 256]`

**Architecture:**
1. **3-Layer 1D CNN:**
   - `Conv1d(1, 64, 7, padding=3)` → `BatchNorm1d(64)` → `GELU` → `MaxPool1d(2)`
   - `Conv1d(64, 128, 5, padding=2)` → `BatchNorm1d(128)` → `GELU` → `MaxPool1d(2)`
   - `Conv1d(128, 256, 3, padding=1)` → `BatchNorm1d(256)` → `GELU` → `MaxPool1d(2)`
   - Output: `[B, 256, 128]`
2. **Attention Pooling:** `Linear(256 → 128) → GELU → Linear(128 → 1)` → softmax scores → weighted sum `[B, 256]`
3. **FC Head:** `Linear(256 → 512) → GELU → LayerNorm(512) → Dropout(0.3) → Linear(512 → 256)`

### 5.5 Stream 4: OptimizedAPIEncoder (API Import Encoder)

**Class:** `OptimizedAPIEncoder`

**Input:** `[B, 256]` int64 API token IDs
**Output:** `[B, 256]`

**Architecture:**
1. **CLS Token:** Learnable parameter `[1, 1, 256]` prepended to sequence
2. **Embedding:** `Embedding(4096, 256, padding_idx=0)` + positional embedding `[1, 257, 256]`
3. **Local CNN Branch** (applied to token embeddings only):
   - `Conv1d(256, 256, 3, padding=1)` → `BatchNorm1d(256)` → `GELU`
   - `Conv1d(256, 256, 3, padding=1)` → `BatchNorm1d(256)` → `GELU`
   - Added back to token positions (not CLS)
4. **Pre-LN Transformer Encoder:** 4 layers, 8 heads, FFN dim 1024, GELU, `norm_first=True`
5. **Output:** CLS token at position 0: `[B, 256]`

### 5.6 Cross-Modal Fusion: OptimizedRansomFormerEncoder

**Class:** `OptimizedRansomFormerEncoder`

**Input:** PE bytes `[B, 1, 1024]` + API tokens `[B, 256]`
**Output:** `[B, 256]`

This encoder implements cross-modal attention between the byte stream and API import stream, inspired by the RansomFormer architecture:

1. `ByteEncoder(pe_bytes)` → byte features `bf [B, 256]`
2. `APIEncoder(api_tokens)` → API features `af [B, 256]`
3. Q = `Linear(256)(bf)`, K = `Linear(256)(af)`, V = `Linear(256)(af)`
4. `MultiheadAttention(8 heads, dropout=0.2)`: Q attends to K,V
5. Residual: `LayerNorm(bf + Dropout(attention_out))`
6. Final: `Linear(256) → LayerNorm(256) → GELU → Dropout(0.2)`

### 5.7 Fusion Head: OptimizedFusion (Deep Residual MLP)

**Class:** `OptimizedFusion`

**Input:** `[B, 1536]` concatenated features (HGT + CNN + RansomFormer)
**Output:** `[B, 2]` logits

**Architecture:**
1. `fc1: Linear(1536 → 1024)` + `GELU` + `LayerNorm(1024)` + `Dropout(0.4)`
2. `fc2: Linear(1024 → 1024)` + residual connection to `fc1` output + `GELU` + `LayerNorm(1024)` + `Dropout(0.4)`
3. `fc3: Linear(1024 → 512)` + `GELU` + `LayerNorm(512)`
4. `head: Linear(512 → 2)` → logits

> **Note:** During Monte Carlo Dropout inference, `sample=True` keeps Dropout layers **active** (even during `eval()` mode) to enable stochastic sampling for uncertainty estimation.

### 5.8 Full Model: JointMalwareModel

**Class:** `JointMalwareModel`

**Forward signature:**
```python
forward(x, ei, nt, et, bi, imgs, pb, at, sample=True) → logits [B, 2]
```

| Argument | Shape | Description |
|---|---|---|
| `x` | `[N, 320]` | CPG node features |
| `ei` | `[2, E]` | CPG edge index |
| `nt` | `[N]` | Node type IDs |
| `et` | `[E]` | Edge type IDs |
| `bi` | `[N]` | Batch index for graph pooling |
| `imgs` | `[B, 3, 224, 224]` | Grayscale images |
| `pb` | `[B, 1, 1024]` | PE byte sequences |
| `at` | `[B, 256]` | API token sequences |

**Forward pass:**
1. `HGT.get_graph_embedding(x, ei, nt, et, bi)` → `g [B, 768]`
2. Move `g` to `rest_device` if needed (multi-device support)
3. `CNN(imgs)` → `i [B, 512]`
4. `RansomFormer(pb, at)` → `r [B, 256]`
5. `concat([g, i, r], dim=-1)` → `[B, 1536]`
6. `Fusion([B, 1536])` → `logits [B, 2]`

**Factory function:**
```python
model = build_model(cfg=NOTEBOOK_CFG, device=torch.device("cuda"))
```

### 5.9 Monte Carlo Dropout Inference

**Method:** `JointMalwareModel.predict_with_confidence()`

Performs `num_samples` (default: 20) stochastic forward passes with Dropout **active** to estimate epistemic (model) uncertainty:

```python
probs = [softmax(forward(..., sample=True)) for _ in range(num_samples)]  # [T, B, C]
mean_probs = stack(probs).mean(0)      # [B, C]
prediction = mean_probs.argmax(-1)     # [B]
confidence = mean_probs[..., pred]     # [B]  highest class probability
variance = stack(probs)[..., pred].var(0)  # [B]  epistemic uncertainty
```

**Output format:**
```python
{
    "file": "suspicious.exe",
    "prediction": 1,           # 0=BENIGN, 1=MALWARE
    "label": "MALWARE",
    "confidence": 0.9438,      # 94.38% confidence
    "variance": 0.000217       # epistemic uncertainty (lower = more certain)
}
```

---

## 6. Training Workflow

### 6.1 Step 1: Dataset Collection

Gather a balanced dataset of:
- **Malware samples:** PE executables (EXE/DLL/SYS), scripts (PS1/JS/BAT), labeled `MALWARE`
- **Benign samples:** Clean system files, installers, legitimate software, labeled `BENIGN`

Organize into:
```
dataset/
├── malwares/   ← malware samples
└── benigns/    ← benign samples
```

### 6.2 Step 2: Feature Extraction

Run the UIR batch processor to extract `.feat.pt` feature bundles:

```bash
# Apple M4 GPU profile
uir batch --input-dir ./dataset/malwares --output-dir ./features/malwares --device-profile m4
uir batch --input-dir ./dataset/benigns  --output-dir ./features/benigns  --device-profile m4

# NVIDIA GPU profile
uir batch --input-dir ./dataset --output-dir ./features --device-profile gtx_1650_ti
```

Each `.feat.pt` file contains all 4 modality tensors for one sample.

**Package for Kaggle:**
```bash
python export_zip.py --features ./features --output vigil_features.zip
```
Upload the zip as a Kaggle dataset.

### 6.3 Step 3: Dataset Classes

**`PreExtractedDataset`** (primary, used in notebook): Loads pre-extracted `.feat.pt` bundles directly, skipping redundant re-processing.

**`CPGDataset`** (from-scratch): Processes raw samples on-the-fly using the full UIR pipeline.

**Data splits:**
- Training: 80%
- Validation: 10%
- Test: 10%

**DataLoader:** Multi-worker parallel loading with custom `collate_fn` to handle heterogeneous CPG batches (variable-size graphs).

### 6.4 Step 4: Kaggle GPU Training

**Notebook:** `traning_notebook/vigil.ipynb`

Run on Kaggle with T4 or P100 GPU. The notebook performs:

1. **Model Initialization:** `build_model(cfg=NOTEBOOK_CFG, device='cuda')`
2. **Optimizer:** `AdamW(model.parameters(), lr=1e-4, weight_decay=1e-4)`
3. **Loss:** `CrossEntropyLoss` with optional label smoothing (`label_smoothing=0.1`)
4. **LR Scheduler:** `CosineAnnealingLR` with optional warmup (5 epochs)
5. **Mixed Precision:** FP16 via `torch.cuda.amp.GradScaler`
6. **EMA:** Exponential Moving Average (decay=0.999) for stable convergence
7. **MC Dropout Validation:** Run 20-sample MC inference on validation set for uncertainty calibration

### 6.5 Training Configuration & Hyperparameters

| Parameter | Default | Environment Variable |
|---|---|---|
| Batch size | 32 | `BATCH_SIZE` |
| Learning rate | 1e-4 | `LEARNING_RATE` |
| Epochs | 100 | `NUM_EPOCHS` |
| Early stopping | 10 | `EARLY_STOPPING_PATIENCE` |
| Dropout | 0.15 | `DROPOUT` |
| Label smoothing | 0.1 | `LABEL_SMOOTHING` |
| Warmup epochs | 5 | `WARMUP_EPOCHS` |
| Min LR | 1e-6 | `MIN_LR` |
| EMA decay | 0.999 | `EMA_DECAY` |
| Feature mask augmentation | 0.15 | `AUG_FEATURE_MASK_RATE` |
| Edge drop augmentation | 0.05 | `AUG_EDGE_DROP_RATE` |

**Evaluation Metrics:** Accuracy, F1-Score (macro), ROC-AUC, Confusion Matrix, MC epistemic variance.

### 6.6 Step 5: Model Deployment

After training on Kaggle:

```bash
# 1. Download joint_model.pt from Kaggle
# 2. Place checkpoint in models directory
cp joint_model.pt models/01/models/joint_model.pt

# 3. Test standalone prediction
python predict.py --file suspicious.exe --samples 20

# 4. Package for deployment
python export_zip.py --checkpoint models/01/models/joint_model.pt --output vigil_deploy.zip
```

**model_config.json** (matches `NOTEBOOK_CFG`):
```json
{
  "embedding_dim": 320,
  "hidden_dim": 384,
  "num_heads": 8,
  "num_layers": 6,
  "num_classes": 2,
  "fused_dim": 1536,
  "byte_seq_len": 1024,
  "max_apis": 256,
  "api_vocab_size": 4096,
  "label_map": {"0": "BENIGN", "1": "MALWARE"},
  "architecture": "OptimizedHGT + ConvNeXt + AttentionByte + CLSTransformerAPI → DeepResMLP"
}
```

---

## 7. Agentic System — Backend

The agentic system is a FastAPI application located in `Agentic_System/backend/`.

### 7.1 FastAPI Entry Point

**File:** `Agentic_System/backend/main.py`

**Application:** `FastAPI(title="ViGil Agentic Malware Analysis System", version="1.0.0")`

**Lifespan events:**
1. Initialize `VigilConfig` and create storage directories
2. Trigger background loading of `ModelPredictor` (lazy-load ML checkpoint)

**CORS:** Allows requests from `FRONTEND_URL` (default: `http://localhost:3000`) with all methods and headers.

**Registered routers:**
- `analysis_router` — `/api/analysis/*`
- `settings_router` — `/api/settings/*`
- `reports_router` — `/api/reports/*`
- `ws_router` — `/ws/*`

**Health endpoint:** `GET /` returns:
```json
{
  "status": "online",
  "title": "ViGil Agentic Malware Analysis System",
  "active_llm_provider": "openai",
  "ml_model_loaded": true,
  "device": "cuda"
}
```

**Running the server:**
```bash
cd Agentic_System
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### 7.2 Configuration System

**File:** `Agentic_System/backend/config.py`

Pydantic-based hierarchical configuration loaded from `.env`:

```
VigilConfig
├── ServerSettings
│   ├── host: "0.0.0.0"          (BACKEND_HOST)
│   ├── port: 8000               (BACKEND_PORT)
│   └── frontend_url: "http://localhost:3000"  (FRONTEND_URL)
├── LLMSettings
│   ├── active_provider: "openai" (LLM_PROVIDER)
│   ├── openai: OpenAIConfig     (OPENAI_API_KEY, OPENAI_MODEL)
│   ├── gemini: GeminiConfig     (GEMINI_API_KEY, GEMINI_MODEL)
│   ├── ollama: OllamaConfig     (OLLAMA_BASE_URL, OLLAMA_MODEL)
│   ├── nvidia_nim: NvidiaNIMConfig  (NVIDIA_NIM_API_KEY, etc.)
│   ├── openrouter: OpenRouterConfig (OPENROUTER_API_KEY, etc.)
│   └── lmstudio: LMStudioConfig    (LMSTUDIO_BASE_URL, etc.)
├── AnalysisSettings
│   ├── mc_dropout_samples: 20   (MC_DROPOUT_SAMPLES)
│   ├── max_recursion_depth: 5   (MAX_RECURSION_DEPTH)
│   ├── max_extracted_files: 1000 (MAX_EXTRACTED_FILES)
│   └── timeout_seconds: 600     (ANALYSIS_TIMEOUT)
└── StoragePaths
    ├── upload_dir               (UPLOAD_DIR)
    ├── reports_dir              (REPORTS_DIR)
    ├── memory_db                (MEMORY_DB_PATH → data/vigil_memory.db)
    ├── knowledge_base           (KNOWLEDGE_BASE_PATH → data/knowledge_base.json)
    ├── model_checkpoint         (MODEL_CHECKPOINT_PATH → models/01/models/joint_model.pt)
    └── model_config_path        (MODEL_CONFIG_PATH → models/01/model_config.json)
```

**API:** `get_config() → VigilConfig` (singleton), `update_config(patch: dict)` for live updates.

### 7.3 Analysis Orchestrator

**File:** `Agentic_System/backend/core/orchestrator.py`
**Class:** `AnalysisOrchestrator`

The master coordinator for the 9-step analysis pipeline:

```
Step 0: Initialize database (LTM.init_db)
Step 1: Compute SHA256 → check LTM cache (return cached if hit)
Step 2: File routing (FileRouter.identify_and_route)
Step 3: Archive extraction (RecursiveExtractor, if container)
Step 4: PE analysis (PEDeepAnalyzer × N files)
       └─ ML inference (ModelPredictor × N files)
       └─ PE Crew (PEAnalysisCrew × N files)
Step 5: Script analysis (ScriptAnalysisCrew × N files)
Step 6: Result aggregation (merge PE + Script verdicts)
Step 7: Persist to LTM (store_analysis)
Step 8: Track IOCs (store_iocs from extracted strings)
Step 9: Update Knowledge Base (update_from_analysis)
       + Cleanup temp extraction directories
       + Emit ANALYSIS_COMPLETED event
```

**Return value** (final results dict):
```python
{
    "analysis_id": "uuid",
    "file_name": "suspicious.exe",
    "file_hash": "sha256...",
    "route": "pe",
    "verdict": "MALWARE",
    "risk_score": 85.0,
    "confidence": 94.0,
    "pe_results": [{
        "file_name": "...",
        "file_hash": "...",
        "static_analysis": { /* 15 analyzer outputs */ },
        "ml_prediction": { "label": "MALWARE", "confidence": 0.94, ... },
        "agent_analysis": { "verdict": "MALWARE", "report_markdown": "..." }
    }],
    "script_results": [...],
    "report_markdown": "# THREAT INTELLIGENCE REPORT..."
}
```

### 7.4 File Router

**File:** `Agentic_System/backend/core/file_router.py`
**Class:** `FileRouter`

Routes files to the appropriate analysis pipeline:

| Route | Trigger File Types | Pipeline |
|---|---|---|
| `pe` | EXE, DLL, SYS, SCR, CPL | PEDeepAnalyzer → ModelPredictor → PEAnalysisCrew |
| `script` | JS, VBS, PS1, BAT, CMD, SH, PY, PL, LUA, PHP, HTA, WSF, AU3, JSE, VBE | ScriptAnalysisCrew |
| `container` | ZIP, 7Z, RAR, GZ, TAR, ISO, IMG, CAB, MSI | RecursiveExtractor → route sub-files |
| `unsupported` | Everything else | Skip (or text-fallback to `script`) |

**Text fallback:** If a file fails type detection but contains only valid UTF-8/Latin-1 text (no null bytes), it is routed as a `script`.

### 7.5 PE Deep Analyzer (15 Modules)

**File:** `Agentic_System/backend/analyzers/pe_deep_analyzer.py`
**Class:** `PEDeepAnalyzer`

All 15 modules run **in parallel** via `asyncio.gather()` in thread pool executors.

| Module | Key | What It Extracts |
|---|---|---|
| `HeaderAnalyzer` | `headers` | DOS header, PE signature, NT/COFF/Optional headers, machine type, subsystem, characteristics, compile timestamp |
| `SectionAnalyzer` | `sections` | Section names, virtual addresses, sizes, raw sizes, entropy per section, flags, anomalies (RWX, size mismatches) |
| `ImportAnalyzer` | `imports` | DLL dependencies, imported API names, suspicious API flags, total import count, API category breakdown |
| `ExportAnalyzer` | `exports` | Exported function names, ordinals, forwarding info |
| `StringExtractor` | `strings` | ASCII/Unicode strings ≥4 chars, extracted URLs, IPs, registry keys, file paths, encoded strings |
| `ResourceAnalyzer` | `resources` | Resource types, language IDs, embedded data sizes, icon/manifest/version info |
| `EntropyAnalyzer` | `entropy` | Overall file entropy, per-section entropy, packed/encrypted region detection |
| `CFGAnalyzer` | `cfg` | Capstone-based disassembly, basic block count, branch count, cyclomatic complexity estimates |
| `APICallGraphAnalyzer` | `api_call_graph` | Cross-section API call relationships, suspicious API sequences |
| `SignatureAnalyzer` | `signatures` | YARA rule matches, matched malware family names |
| `PackerDetector` | `packer` | UPX, MPRESS, Themida, ASPack, etc. detection, `is_packed` flag |
| `DebugFeatureAnalyzer` | `debug_features` | Anti-debug API imports (IsDebuggerPresent, CheckRemoteDebugger, etc.), timing checks, RDTSC |
| `CertificateAnalyzer` | `certificate` | Authenticode certificate chain, subject, issuer, validity, signature verification status |
| `OverlayAnalyzer` | `overlay` | Data appended after last section (common in self-extractors and droppers) |
| `MemoryLayoutAnalyzer` | `memory_layout` | Virtual memory map reconstruction, section alignments |

### 7.6 ML Model Predictor

**File:** `Agentic_System/backend/ml/model_predictor.py`
**Class:** `ModelPredictor` (Singleton)

**Device auto-detection order:** CUDA → MPS (Apple Silicon) → CPU

**Lazy loading:** Model checkpoint is loaded in a thread pool executor at startup to avoid blocking the asyncio event loop. The `load_model()` coroutine uses `predict.py` functions (`_load_model_cfg`, `_build_model`, `_load_checkpoint`).

**Inference:** `predict(file_path, num_samples=20)` runs in a thread pool executor, calling `predict.predict()` which extracts features on-the-fly and runs MC Dropout inference.

**Key methods:**
- `is_loaded() → bool`
- `load_model() → bool`
- `predict(file_path, num_samples) → dict`
- `get_model_info() → dict`

### 7.7 AI Agent Crews (CrewAI)

The agentic system uses the **CrewAI** framework (v0.80.0+) to orchestrate LLM-powered security analysts. All crews use `Process.sequential` with task dependencies.

**LLM Temperature:** `0.1` (low randomness for consistent, factual security analysis)

### 7.8 PE Analysis Crew — 8 Agents

**File:** `Agentic_System/backend/agents/pe_crew.py`
**Class:** `PEAnalysisCrew`

**Input context:** Merged JSON of `pe_static_analysis` (15 analyzer outputs) + `ml_model_prediction`

#### Phase 1: Parallel Execution (5 agents, `async_execution=True`)

| Agent | Role | Input Focus | Output |
|---|---|---|---|
| **Structural Analyst** | Senior PE Structural Analyst | headers, sections, entropy, packer data | Structural anomalies, RWX sections, packing indicators |
| **Import Behavior** | API Import Behavior Analyst | imports, exports, api_call_graph | Malicious DLL/API patterns, suspicious import sets |
| **Network Intel** | Network Intelligence Analyst | strings (URLs, IPs), network patterns | C2 indicators, suspicious domains, IP reputation |
| **Evasion Specialist** | Evasion & Obfuscation Specialist | entropy, packer, debug_features, resources | Anti-debug tricks, VM detection, obfuscation techniques |
| **String NLP** | String & NLP Intelligence Analyst | strings, signatures | IOC extraction from strings, YARA match analysis |

All 5 run concurrently. When all 5 complete, the Results Coordinator is triggered.

#### Phase 2: Sequential Execution (3 agents)

| Agent | Role | Input | Output |
|---|---|---|---|
| **Results Coordinator** | Results Analysis Coordinator | All 5 parallel agent outputs | Synthesized findings, preliminary verdict |
| **Model Comparator** | ML Model & Agent Consensus Analyst | Coordinator output + ML prediction | Consensus verdict, risk score, confidence |
| **Report Generator** | Senior Threat Intelligence Report Writer | All agent outputs | Final Markdown threat intelligence report |

**Report Format (exact template):**
```markdown
# THREAT INTELLIGENCE & FORENSICS REPORT
# VERDICT: MALWARE
## CONFIDENCE: 94% | VIGIL THREAT MATRIX SCORE: 85/100
---
## 1. Executive Summary
## 2. File Metadata & Overview
## 3. Consensus & Logic Chain
## 4. In-Depth Technical Analysis
   ### A. Static Forensics & Indicators
   ### B. Evasion & Anti-Analysis Detection
   ### C. Network & C2 Indicators (IOCs)
## 5. MITRE ATT&CK Mapping
## 6. Defensive Recommendations & Mitigation
```

**Verdict parsing:** The orchestrator parses `VERDICT: MALWARE` / `VERDICT: BENIGN` from the report and model comparator outputs using regex fallbacks.

**WebSocket events emitted:**
- `AGENT_STARTED` for each of the 5 parallel agents at launch
- `AGENT_COMPLETED` via task callbacks on completion
- `AGENT_STARTED` for Results Coordinator when all 5 parallel agents finish
- `AGENT_STARTED`/`AGENT_COMPLETED` for each sequential agent

### 7.9 Script Analysis Crew — 1 Agent

**File:** `Agentic_System/backend/agents/script_crew.py`
**Class:** `ScriptAnalysisCrew`

**Agent:** Universal Script Threat Analyst

**Capabilities:**
1. Language & Obfuscation identification (Base64, hex, XOR decoding)
2. Suspicious behavior detection (credential theft, LOLBin abuse, registry, process injection)
3. Persistence & Evasion (startup entries, scheduled tasks, VM/sandbox detection)
4. MITRE ATT&CK technique mapping
5. Risk score (0–100) + Verdict + Confidence calculation

**Input:** Script source code (truncated to 20,000 characters to avoid token limits)
**Output:** Same Markdown report template as PE crew (adapted for scripts)

**Script truncation limit:** 20,000 characters

### 7.10 LLM Configuration Factory

**File:** `Agentic_System/backend/agents/llm_config.py`

`get_llm(provider_config=None) → crewai.LLM`

Supported providers with default models:

| Provider ID | Default Model | Auth |
|---|---|---|
| `openai` | `gpt-4o` | `OPENAI_API_KEY` |
| `gemini` | `gemini-2.5-flash` | `GEMINI_API_KEY` |
| `ollama` | `llama3` | None (local, `OLLAMA_BASE_URL`) |
| `nvidia_nim` | `meta/llama-3.1-70b-instruct` | `NVIDIA_NIM_API_KEY` |
| `openrouter` | `anthropic/claude-sonnet-4` | `OPENROUTER_API_KEY` |
| `lmstudio` | `local-model` | None (local, `LMSTUDIO_BASE_URL`) |

**Model name format:** All models are passed with a provider prefix (e.g., `openai/gpt-4o`, `gemini/gemini-2.5-flash`) to CrewAI's `LLM` class.

**`test_connection(provider_config)`**: Sends a `"Respond with 'pong'"` prompt and measures response time in milliseconds.

### 7.11 Memory System

ViGil implements a 4-tier memory architecture:

#### Long-Term Memory (LongTermMemory)
**File:** `Agentic_System/backend/memory/long_term.py`

- **Backend:** SQLite via `aiosqlite` (fully async)
- **Pattern:** Singleton
- **DB Location:** `Agentic_System/data/vigil_memory.db`

**Tables:**

```sql
analyses (
    id TEXT PRIMARY KEY,
    file_hash TEXT UNIQUE,   -- SHA256 for cache deduplication
    file_name TEXT,
    file_type TEXT,
    verdict TEXT,
    confidence REAL,
    risk_score REAL,
    full_results_json TEXT,  -- Complete results as JSON string
    report_markdown TEXT,
    created_at TEXT          -- ISO 8601 UTC
)

iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT → analyses(id) ON DELETE CASCADE,
    ioc_type TEXT,           -- "url", "ip", "domain", "hash"
    ioc_value TEXT,
    context TEXT,
    threat_level INTEGER,    -- 0-10
    created_at TEXT
)
-- Indexed on: ioc_value

agent_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT → analyses(id) ON DELETE CASCADE,
    agent_name TEXT,
    result_json TEXT,
    created_at TEXT
)
```

**Key operations:**
- `store_analysis()` — `INSERT OR REPLACE` for idempotent storage
- `get_analysis_by_hash(sha256)` — Cache lookup to skip redundant analysis
- `get_recent_analyses(limit=50)` — Dashboard history
- `store_iocs(analysis_id, iocs[])` — Bulk IOC persistence
- `search_ioc(ioc_value)` — Cross-analysis IOC correlation

#### Knowledge Base (KnowledgeBase)
**File:** `Agentic_System/backend/memory/knowledge_base.py`

- **Backend:** JSON file (`data/knowledge_base.json`)
- **Pattern:** Singleton

**Schema:**
```json
{
  "malware_families": {},     // name → {last_seen_file, sample_size}
  "ttps": {},                 // MITRE technique ID → details
  "evasion_techniques": {},   // API name → frequency count
  "behavioral_patterns": [],  // Observed pattern strings
  "ioc_patterns": {}          // domain → frequency count
}
```

**Auto-updated** after every analysis via `update_from_analysis()`, which extracts:
- Matched YARA malware family names → `malware_families`
- Anti-debug API names → `evasion_techniques` (frequency counts)
- Extracted domains from URLs → `ioc_patterns` (frequency counts)

#### Short-Term Memory (ShortTermMemory)
**File:** `Agentic_System/backend/memory/short_term.py`

- **Backend:** Python dict in memory
- **Pattern:** Singleton with `asyncio.Lock()` for thread safety
- **Scope:** Per analysis session; cleared when analysis completes

**Operations:** `store()`, `retrieve()`, `get_all()`, `store_agent_result()`, `get_agent_results()`, `clear()`

#### Entity Memory (EntityMemory)
**File:** `Agentic_System/backend/memory/entity_memory.py`

Provides cross-analysis IOC correlation built on top of `LongTermMemory`.

**Operations:**
- `track_entity(type, value, analysis_id, context, threat_level)` — Register an IOC entity
- `get_entity_history(type, value)` — All analyses where this entity was seen
- `get_related_entities(entity_value)` — Co-occurring entities from same analyses
- `get_high_risk_entities(min_threat_level=7)` — High-risk IOC tracking

### 7.12 Event Emitter (WebSocket SSE)

**File:** `Agentic_System/backend/core/event_emitter.py`
**Class:** `EventEmitter` (Singleton via `get_emitter()`)

**Architecture:**
- `_subscribers: Dict[analysis_id, Set[WebSocket]]` — Session-specific channels
- `_global_subscribers: Set[WebSocket]` — Global dashboard channels
- `_history: Dict[analysis_id, List[str]]` — Event replay buffer (max 500 events per session)

**Event Types (EventType enum):**

| Category | Events |
|---|---|
| Pipeline | `analysis_started`, `analysis_completed`, `analysis_failed` |
| Steps | `step_started`, `step_progress`, `step_completed`, `step_failed` |
| Agents | `agent_started`, `agent_thinking`, `agent_tool_use`, `agent_completed`, `agent_failed` |
| Results | `pe_analysis_ready`, `ml_prediction_ready`, `agent_result_ready`, `report_ready` |
| Files | `file_identified`, `files_extracted` |
| System | `system_status`, `log` |

**AnalysisEvent data model:**
```python
{
    "event_type": "agent_completed",
    "analysis_id": "uuid",
    "timestamp": "2026-06-11T06:00:00.000000+00:00",
    "step": "agents_analysis",
    "agent": "Senior PE Structural Analyst",
    "progress": 0.75,
    "message": "Structural Analyst completed analysis.",
    "data": { "output": "# Structural Analysis..." }
}
```

**Late-joiner support:** New WebSocket connections receive the full event history for their `analysis_id`, enabling page reloads without missing progress.

---

## 8. API Reference

### 8.1 Analysis Endpoints

**Base path:** `/api/analysis`

#### `POST /api/analysis/upload`
Upload a file for analysis.

**Request:** `multipart/form-data` with `file` field

**Response:**
```json
{
  "analysis_id": "uuid-v4",
  "file_name": "suspicious.exe",
  "file_size": 102400,
  "status": "queued"
}
```

Analysis runs in a **background task** (non-blocking). Monitor progress via WebSocket `/ws/{analysis_id}`.

#### `GET /api/analysis/history?limit=50`
Retrieve recent analysis history from SQLite.

**Response:** Array of analysis records with `id`, `file_hash`, `file_name`, `file_type`, `verdict`, `confidence`, `risk_score`, `created_at`.

#### `GET /api/analysis/{analysis_id}`
Get status or results of an analysis.

**Response (in-flight):**
```json
{"status": "identifying", "progress": 0.1, "file_name": "...", ...}
```

**Response (completed):**
```json
{"status": "completed", "progress": 1.0, "results": {...}, "report": "# THREAT..."}
```

#### `GET /api/analysis/{analysis_id}/report`
Get the Markdown report text.

#### `GET /api/analysis/{analysis_id}/json`
Get raw full results JSON.

#### `DELETE /api/analysis/{analysis_id}`
Delete an analysis from memory and SQLite.

### 8.2 Reports Endpoints

**Base path:** `/api/reports`

| Endpoint | Method | Description |
|---|---|---|
| `/api/reports/recent?limit=20` | GET | List recent reports (id, file_name, verdict, risk_score, created_at) |
| `/api/reports/{analysis_id}` | GET | Get report Markdown content |
| `/api/reports/{analysis_id}/download` | GET | Download report as `.md` file (FileResponse) |

### 8.3 Settings Endpoints

**Base path:** `/api/settings`

| Endpoint | Method | Description |
|---|---|---|
| `/api/settings` | GET | Get current settings (API keys masked) |
| `/api/settings` | PUT | Update settings (masked keys are preserved) |
| `/api/settings/test-connection` | POST | Test LLM provider connection (ping/pong, returns `response_time_ms`) |
| `/api/settings/providers` | GET | List all supported providers with required fields |

**Security:** API keys are masked in GET responses — only last 4 characters shown. Masked keys in PUT payloads are automatically replaced with stored originals.

### 8.4 WebSocket Endpoints

#### `WS /ws/{analysis_id}`
Session-specific event stream. Connects to events for a single analysis.

- On connect: Replays event history for late-joiners
- Messages: JSON `AnalysisEvent` objects
- Ping/pong: Client sends `{"type":"ping"}`, server responds `{"type":"pong"}`

#### `WS /ws/global`
Global dashboard stream. Receives ALL analysis events from ALL sessions.

---

## 9. Agentic System — Frontend

**Framework:** Next.js 14 (App Router)
**Port:** 3000

### 9.1 Pages & Routing

| Route | File | Description |
|---|---|---|
| `/` | `src/app/page.js` | Dashboard: file upload, recent analyses, system status |
| `/analysis/[id]` | `src/app/analysis/` | Live analysis view with agents chat, report viewer, risk gauge |
| `/settings` | `src/app/settings/` | LLM provider configuration and connection testing |

**Dashboard** (`page.js`) features:
- Hero header with ViGil branding
- `FileUpload` component (drag-and-drop)
- Recently processed samples list with verdict badges
- Engine status panel (backend status, ML model state, active provider, compute device)

### 9.2 Components

| Component | File | Description |
|---|---|---|
| `FileUpload` | `FileUpload.jsx` | Drag-and-drop file upload with progress bar |
| `AgentsChat` | `AgentsChat.jsx` | Live terminal showing agent thoughts and outputs |
| `AgentCard` | `AgentCard.jsx` | Individual agent status card with role and output |
| `AgentActivity` | `AgentActivity.jsx` | Activity indicator for running agents |
| `AnalysisProgress` | `AnalysisProgress.jsx` | Step-by-step progress display |
| `ReportViewer` | `ReportViewer.jsx` | Markdown threat report renderer |
| `RiskGauge` | `RiskGauge.jsx` | Semi-circular risk score gauge visualization |
| `EntropyChart` | `EntropyChart.jsx` | Section entropy bar chart |
| `SettingsPanel` | `SettingsPanel.jsx` | Provider selection + API key configuration |
| `Header` | `Header.jsx` | Top navigation bar |
| `Sidebar` | `Sidebar.jsx` | Left navigation sidebar |

**WebSocket integration:** The analysis page connects to `/ws/{analysis_id}` and updates UI state in real-time as agent events arrive.

---

## 10. Supported File Types

| Category | Extensions | Analysis Pipeline |
|---|---|---|
| **PE Executables** | .exe, .dll, .sys, .scr, .cpl | PEDeepAnalyzer (15 modules) → ML Model → 8 PE Agents |
| **Scripts** | .js, .vbs, .ps1, .bat, .cmd, .sh, .py, .pl, .lua, .php, .hta, .wsf, .au3, .jse, .vbe | Script Crew (1 agent) |
| **Office Documents** | .doc, .docx, .docm, .xls, .xlsx, .xlsm, .xll, .ppt, .pptx, .ppam | DocumentLifter → CPG extraction |
| **Rich Documents** | .pdf, .rtf | DocumentLifter |
| **Archives** | .zip, .7z, .rar, .gz, .tar, .iso, .img, .cab | RecursiveExtractor → route sub-files |
| **Installers** | .msi, .dmg | MSIExtractor → route sub-files |
| **Launchers** | .lnk, .url, .desktop | LauncherLifter |

---

## 11. Installation & Setup

### UIR Library (ML Core)

```bash
cd /path/to/ViGil
pip install -e .           # Install UIR as editable package

# GPU support
pip install -e ".[gpu]"
```

### Agentic System Backend

```bash
cd Agentic_System
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your LLM API keys and settings

# Start backend
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### Agentic System Frontend

```bash
cd Agentic_System/frontend
npm install
npm run dev     # Development server on port 3000
```

### Place ML Model Checkpoint

```bash
# After training or downloading the checkpoint
mkdir -p models/01/models/
cp joint_model.pt models/01/models/joint_model.pt
cp model_config.json models/01/model_config.json
```

---

## 12. Configuration Reference

### `.env` (Agentic System)

```env
# ── LLM Provider ──────────────────────────────────────────────
LLM_PROVIDER=openai              # openai|gemini|ollama|nvidia_nim|openrouter|lmstudio

# OpenAI
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o

# Google Gemini
GEMINI_API_KEY=AIza...
GEMINI_MODEL=gemini-2.5-flash

# Ollama (local)
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3

# NVIDIA NIM
NVIDIA_NIM_API_KEY=...
NVIDIA_NIM_BASE_URL=https://integrate.api.nvidia.com/v1
NVIDIA_NIM_MODEL=meta/llama-3.1-70b-instruct

# OpenRouter
OPENROUTER_API_KEY=...
OPENROUTER_MODEL=anthropic/claude-sonnet-4

# LM Studio (local)
LMSTUDIO_BASE_URL=http://localhost:1234/v1
LMSTUDIO_MODEL=local-model

# ── Server ─────────────────────────────────────────────────────
BACKEND_HOST=0.0.0.0
BACKEND_PORT=8000
FRONTEND_URL=http://localhost:3000

# ── Analysis ──────────────────────────────────────────────────
MC_DROPOUT_SAMPLES=20
MAX_RECURSION_DEPTH=5
MAX_EXTRACTED_FILES=1000
ANALYSIS_TIMEOUT=600

# ── Storage Paths ─────────────────────────────────────────────
UPLOAD_DIR=uploads
REPORTS_DIR=reports
MEMORY_DB_PATH=data/vigil_memory.db
KNOWLEDGE_BASE_PATH=data/knowledge_base.json
MODEL_CHECKPOINT_PATH=../models/01/models/joint_model.pt
MODEL_CONFIG_PATH=../models/01/model_config.json
```

### UIR Environment Variables

```env
# Model architecture
EMBEDDING_DIM=320
HIDDEN_DIM=256
NUM_HEADS=8
NUM_LAYERS=4
DROPOUT=0.15
NUM_CLASSES=2

# Training
BATCH_SIZE=32
LEARNING_RATE=1e-4
NUM_EPOCHS=100
EARLY_STOPPING_PATIENCE=10
TRAIN_RATIO=0.8
VAL_RATIO=0.1
TEST_RATIO=0.1
LR_SCHEDULER_TYPE=cosine_warmup
WARMUP_EPOCHS=5
MIN_LR=1e-6
LABEL_SMOOTHING=0.1
USE_FOCAL_LOSS=false
FOCAL_LOSS_GAMMA=2.0
USE_EMA=true
EMA_DECAY=0.999
USE_AUGMENTATION=true
AUG_FEATURE_MASK_RATE=0.15
AUG_EDGE_DROP_RATE=0.05
USE_CONTRASTIVE_LOSS=true
CONTRASTIVE_TEMPERATURE=0.07
```

---

## 13. CLI Reference

### `uir` commands (installed via `pip install -e .`)

```bash
# Single file CPG generation
uir process \
  --input suspicious.exe \
  --output suspicious.cpg.json \
  --verbose

# Batch processing → .feat.pt bundles
uir batch \
  --input-dir ./dataset \
  --output-dir ./features \
  --device-profile m4           # or gtx_1650_ti, cpu_default, auto

# Predict via CLI
uir predict \
  --model models/01/models/joint_model.pt \
  --input suspicious.exe \
  --samples 20

# Export trained model as deployment ZIP
python export_zip.py \
  --checkpoint models/01/models/joint_model.pt \
  --output vigil_deploy.zip
```

---

## 14. Prediction Script

**File:** `predict.py`

Standalone command-line predictor for single-file analysis:

```bash
python predict.py --file suspicious.exe

# Full options
python predict.py \
  --file suspicious.exe \
  --model models/01/models/joint_model.pt \
  --samples 20 \
  --device auto \
  --verbose \
  --json
```

**Options:**

| Flag | Default | Description |
|---|---|---|
| `--file / -f` | *(required)* | File to analyze |
| `--model / -m` | `models/01/models/joint_model.pt` | Model checkpoint path |
| `--samples / -s` | `20` | Monte Carlo dropout samples |
| `--device` | `auto` | `auto` / `cpu` / `cuda` / `mps` |
| `--verbose / -v` | off | Verbose logging |
| `--json` | off | Output raw JSON |

**Example output:**
```
==================================================================
  ViGil — Quad-Modal Malware Detection
  Architecture: OptimizedHGT + ConvNeXt + AttentionByte + CLSTransformerAPI → DeepResMLP
==================================================================
  File:        suspicious.exe
  Verdict:     MALWARE
  Confidence:  94.38%
  Uncertainty: 0.000217  (epistemic variance, MC dropout)
==================================================================
```

---

## 15. Dependencies Reference

### UIR / ML Core (`requirements.txt`)

| Package | Purpose |
|---|---|
| `pefile` | PE file parsing |
| `python-magic-bin` | File type detection (libmagic) |
| `py7zr` | 7-Zip extraction |
| `rarfile` | RAR extraction |
| `pycdlib` | ISO/IMG disk image extraction |
| `oletools` | Office OLE document analysis |
| `tree-sitter` | AST generation for scripts |
| `torch ≥2.0` | PyTorch deep learning framework |
| `torch-geometric ≥2.4` | Graph neural network support |
| `networkx` | Graph analysis utilities |
| `tqdm` | Progress bars |
| `pydantic ≥2.0` | Configuration validation |
| `numpy` | Numerical operations |
| `scikit-learn` | Evaluation metrics |
| `pylnk3` | LNK shortcut parsing |
| `orjson` | Fast JSON serialization |
| `msgpack` | Binary serialization (M4 optimization) |
| `transformers` | Pre-trained transformer models |
| `peft` | Parameter-efficient fine-tuning |
| `pillow` | Image processing |

### Agentic System (`Agentic_System/requirements.txt`)

| Package | Purpose |
|---|---|
| `fastapi ≥0.115` | Web framework |
| `uvicorn[standard]` | ASGI server |
| `python-multipart` | File upload parsing |
| `websockets ≥12.0` | WebSocket support |
| `pydantic-settings ≥2.0` | Settings management |
| `aiofiles` | Async file I/O |
| `python-dotenv` | `.env` loading |
| `pefile` | PE binary parsing |
| `yara-python ≥4.5` | YARA signature matching |
| `capstone ≥5.0` | Disassembly engine (CFG analysis) |
| `signify ≥0.6` | Authenticode certificate parsing |
| `crewai[tools] ≥0.80` | Multi-agent orchestration |
| `langchain ≥0.3` | LLM abstraction layer |
| `langchain-openai` | OpenAI LangChain integration |
| `langchain-google-genai` | Gemini LangChain integration |
| `aiosqlite ≥0.20` | Async SQLite operations |

---

## 16. Security Considerations

> [!WARNING]
> ViGil analyzes potentially malicious files. The following security practices are mandatory.

1. **Sandboxed Execution:** The analysis backend should ideally run in a containerized environment (Docker) with no network access, as malware samples are processed locally.

2. **File Upload Sanitization:** All uploaded filenames are sanitized by stripping non-alphanumeric characters before saving (`safe_name` logic in `analysis.py`). Temporary files are deleted after analysis.

3. **API Key Storage:** API keys are stored in `.env` files only. They are never logged and are masked in all API responses.

4. **Archive Extraction Limits:** `MAX_RECURSION_DEPTH=5` and `MAX_EXTRACTED_FILES=1000` prevent zip-bomb attacks.

5. **Analysis Timeout:** `ANALYSIS_TIMEOUT=600` (10 minutes) prevents hung analyses from consuming resources indefinitely.

6. **No Code Execution:** ViGil performs **static analysis only** — malware samples are never executed.

7. **LLM Context Sanitization:** Script content is truncated to 20,000 characters before being sent to LLM providers to prevent prompt injection from malicious scripts.

8. **SQLite Injection Prevention:** All database queries use parameterized statements (`?` placeholders) via `aiosqlite`.

---

## References

- **RansomFormer:** Byte + API cross-modal encoder architecture inspiration.
  *Electronics 14(7):1245, 2025.* [DOI:10.3390/electronics14071245](https://doi.org/10.3390/electronics14071245)
- **ConvNeXt:** A ConvNet for the 2020s. Liu et al., 2022.
- **HGT:** Heterogeneous Graph Transformer. Hu et al., 2020.
- **CrewAI:** [crewai.com](https://crewai.com) — Multi-agent collaboration framework.
- **MITRE ATT&CK:** [attack.mitre.org](https://attack.mitre.org) — Adversary tactics and techniques knowledge base.

---

*Documentation generated for ViGil v1.0.0 — © 2026 ViGil Security*
