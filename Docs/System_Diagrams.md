# ViGil Malware Forensics Platform — System Diagrams Reference

This document compiles the light-theme high-resolution system diagrams for the ViGil Quad-Modal and Agentic Threat Forensics Platform. It includes links to generated high-resolution assets and responsive Mermaid vector specifications for all 7 architectural views.

---

## 1. Full System Architecture
Illustrates the end-to-end payload analysis flow, detailing the parallel paths of the Deep Learning pipeline and the Agentic swarm.

![Full System Architecture](/Users/sasindumalhara/Workspace/ViGil/Docs/full_system_architecture.png)

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#f8fafc', 'primaryTextColor': '#0f172a', 'primaryBorderColor': '#cbd5e1', 'lineColor': '#475569', 'secondaryColor': '#f1f5f9', 'tertiaryColor': '#f8fafc' }}}%%
flowchart TD
    subgraph DL_Pipeline ["Deep Learning Pipeline"]
        A[File Upload] --> B[File Parsing & Normalization]
        B --> C1[1. CPG Graph - OptimizedHGT]
        B --> C2[2. Image/Visual - ConvNeXt]
        B --> C3[3. Bytes Sequence - RansomFormer]
        B --> C4[4. API Call Sequence - RansomFormer]
        C1 --> D[Deep Residual MLP Prediction]
        C2 --> D
        C3 --> D
        C4 --> D
        D --> E[High-Confidence Classification]
    end

    subgraph Agent_Swarm ["Agentic Forensic Swarm"]
        F[(SQLite DB)] <--> G[FastAPI Backend]
        H[WebSocket Emitter] -.-> G
        G --> I[Agentic Orchestrator]
        I --> J1[PE Swarm - 8 Agents]
        I --> J2[Script Swarm - 1 Agent]
        J1 --> K[Consolidated Knowledge & Verdict]
        J2 --> K
    end

    E --> K
    K --> L[Actionable Threat intelligence Report]

    classDef default fill:#f8fafc,stroke:#cbd5e1,stroke-width:1px,color:#0f172a;
    classDef highlight fill:#e0f2fe,stroke:#0284c7,stroke-width:1.5px,color:#0369a1;
    classDef purpleHighlight fill:#f3e8ff,stroke:#8b5cf6,stroke-width:1.5px,color:#6b21a8;
    classDef greenHighlight fill:#dcfce7,stroke:#22c55e,stroke-width:1.5px,color:#166534;
    
    class A,B,E highlight;
    class D,I,K purpleHighlight;
    class L greenHighlight;
```

---

## 2. Agentic System Architecture
Focuses exclusively on the frontend, backend routes, database structures, and CrewAI connection flows.

![Agentic System Architecture](/Users/sasindumalhara/Workspace/ViGil/Docs/agentic_system_architecture.png)

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#f8fafc', 'primaryTextColor': '#0f172a', 'primaryBorderColor': '#cbd5e1', 'lineColor': '#475569' }}}%%
flowchart LR
    subgraph Frontend ["Next.js Frontend Client"]
        A1[Dashboard Page]
        A2[Settings Panel]
        A3[Tab Views]
        A4[Interactive Chat]
    end

    subgraph Backend ["FastAPI Backend Server"]
        B1[websocket.py]
        B2[analysis.py]
        B3[reports.py]
    end

    subgraph Memory ["Storage Layer"]
        C[(SQLite3 LTM DB)]
        C1[(analyses table)]
        C2[(iocs table)]
    end

    subgraph CrewAI ["CrewAI Agent Executor"]
        D1[PE Consensus Swarm]
        D2[Script Analyst Agent]
    end

    A4 <-->|WebSocket Real-time events| B1
    A1 & A2 & A3 -->|REST APIs| B2 & B3
    B2 & B3 <-->|SQL Queries| C
    B2 & B3 <-->|Kickoff Thread| CrewAI
    B1 -.->|Task Callbacks| CrewAI
    C --> C1 & C2

    classDef default fill:#f8fafc,stroke:#cbd5e1,stroke-width:1px,color:#0f172a;
    classDef highlight fill:#e0f2fe,stroke:#0284c7,stroke-width:1.5px,color:#0369a1;
    classDef greenHighlight fill:#dcfce7,stroke:#22c55e,stroke-width:1.5px,color:#166534;
    classDef amberHighlight fill:#fef9c3,stroke:#eab308,stroke-width:1.5px,color:#854d0e;

    class A4,B1 highlight;
    class B2,D1,D2 greenHighlight;
    class C,C1,C2 amberHighlight;
```

---

## 3. until ML Model Training Pipeline
Illustrates the engineering flow from raw payload files down to serialization and Kaggle GPU model training.

![ML Training Pipeline](/Users/sasindumalhara/Workspace/ViGil/Docs/ml_training_pipeline.png)

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#f8fafc', 'primaryTextColor': '#0f172a', 'primaryBorderColor': '#cbd5e1', 'lineColor': '#475569' }}}%%
flowchart TD
    A[Raw Payload Files] -->|Ingestion| B[Extraction & Decompilation]
    B -->|Lifting Binaries| B1[Ghidra decompilation to P-Code]
    B -->|Parsing Scripts| B2[Tree-sitter AST parsing]
    B1 & B2 --> C[Feature Engineering]
    C -->|Vectorization| C1[320-dim Node Feature Construction]
    C1 --> D[Code Property Graph Generation]
    D -->|Define Edges| D1[AST, CFG, PDG Graph representation]
    D1 --> E[Pt Dataset Bundle Serialization]
    E -->|Write bundles| E1[.feat.pt Files]
    E1 -->|Upload dataset| F[Kaggle GPU T4 Model Training]
    F -->|Run Notebook| G[joint_model.pt Checkpoints]

    classDef default fill:#f8fafc,stroke:#cbd5e1,stroke-width:1px,color:#0f172a;
    classDef highlight fill:#e0f2fe,stroke:#0284c7,stroke-width:1.5px,color:#0369a1;
    classDef purpleHighlight fill:#f3e8ff,stroke:#8b5cf6,stroke-width:1.5px,color:#6b21a8;

    class A,E1 highlight;
    class G,F purpleHighlight;
```

---

## 4. ML Model Architecture
Represents the neural network design of the Quad-Modal Joint Malware Model detailing dimensional transformations and fusion.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#f8fafc', 'primaryTextColor': '#0f172a', 'primaryBorderColor': '#cbd5e1', 'lineColor': '#475569' }}}%%
flowchart TD
    subgraph Stream1 ["Graph Stream"]
        A1[CPG Node Features] -->|320-dim| B1[OptimizedHGT - 6-layer 8-head HGT]
        B1 -->|JK residual + Attn Pooling| C1[Graph Embedding - 768-dim]
    end

    subgraph Stream2 ["Visual Stream"]
        A2[Byte-Density Image] -->|224x224x3| B2[ConvNeXt-Tiny CNN]
        B2 -->|Spatial Average Pooling| C2[Visual Embedding - 512-dim]
    end

    subgraph Stream3 ["RansomFormer Stream"]
        A3a[Raw Bytes Window] -->|1024-byte 1D CNN| B3a[Byte Embeds - 256-dim]
        A3b[API Import Tokens] -->|256 token Pre-LN Trans| B3b[API Embeds - 256-dim]
        B3a & B3b -->|Multi-Head Cross Attention| C3[Byte/API Cross Embedding - 256-dim]
    end

    C1 & C2 & C3 -->|Concatenation| D[Fused Vector - 1536-dim]
    D --> E[Deep Residual MLP Projection]
    E -->|GELU + LayerNorm + 40% Dropout| F[Inference Head]
    F -->|Monte Carlo Dropout Sampling| G[Classification Output]
    G -->|T passes argmax| H[Verdict & Confidence]

    classDef default fill:#f8fafc,stroke:#cbd5e1,stroke-width:1px,color:#0f172a;
    classDef highlight fill:#e0f2fe,stroke:#0284c7,stroke-width:1.5px,color:#0369a1;
    classDef purpleHighlight fill:#f3e8ff,stroke:#8b5cf6,stroke-width:1.5px,color:#6b21a8;

    class C1,C2,C3 highlight;
    class D,E,F,H purpleHighlight;
```

---

## 5. AI Agents Architecture
Displays the organizational structure, roles, and groupings of the CrewAI forensic agents.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#f8fafc', 'primaryTextColor': '#0f172a', 'primaryBorderColor': '#cbd5e1', 'lineColor': '#475569' }}}%%
flowchart TD
    subgraph PE_Crew ["PE Forensics Swarm"]
        direction TB
        subgraph Parallel_PE ["Parallel Specialist Analysts"]
            A1[Senior PE Structural Analyst]
            A2[API Import Behavior Analyst]
            A3[Network Intelligence Analyst]
            A4[Evasion & Obfuscation Specialist]
            A5[String & NLP Intelligence Analyst]
        end
        
        B[Results Analysis Coordinator]
        C[ML Model & Agent Consensus Analyst]
        D[Senior Threat Intelligence Report Writer]

        Parallel_PE -->|Task Completion| B
        B -->|Synthesized Context| C
        C -->|Authoritative Verdict| D
    end

    subgraph Script_Crew ["Script Forensics Swarm"]
        E[Universal Script Threat Analyst]
    end

    classDef default fill:#f8fafc,stroke:#cbd5e1,stroke-width:1px,color:#0f172a;
    classDef highlight fill:#e0f2fe,stroke:#0284c7,stroke-width:1.5px,color:#0369a1;
    classDef purpleHighlight fill:#f3e8ff,stroke:#8b5cf6,stroke-width:1.5px,color:#6b21a8;
    classDef greenHighlight fill:#dcfce7,stroke:#22c55e,stroke-width:1.5px,color:#166534;

    class A1,A2,A3,A4,A5 highlight;
    class B,C purpleHighlight;
    class D,E greenHighlight;
```

---

## 6. AI Agents Dataflow Architecture
Details how information and files route between backend analyzers, the model consensus engine, and reporting modules.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#f8fafc', 'primaryTextColor': '#0f172a', 'primaryBorderColor': '#cbd5e1', 'lineColor': '#475569' }}}%%
flowchart TD
    A[Static Analysis JSON Dump] -->|Context Injection| B1 & B2 & B3 & B4 & B5
    
    subgraph Swarm_Execution ["Parallel Swarm Execution"]
        B1[PE Structural Analyst] -->|Entropy & Section report| C[Results Coordinator]
        B2[API Import Analyst] -->|API behaviors report| C
        B3[Network Intel Analyst] -->|Network IOCs report| C
        B4[Evasion Specialist] -->|Anti-Debug & VM report| C
        B5[String NLP Analyst] -->|String semantics report| C
    end

    D[PyTorch ML Predictor JSON] -->|ML Verdict & Confidence| E[Consensus Analyst]
    C -->|Unified Analyst findings| E
    E -->|Consensus Verdict & Threat Score| F[Threat Report Writer]
    F -->|Render markdown| G[Premium Forensics Report]

    classDef default fill:#f8fafc,stroke:#cbd5e1,stroke-width:1px,color:#0f172a;
    classDef highlight fill:#e0f2fe,stroke:#0284c7,stroke-width:1.5px,color:#0369a1;
    classDef purpleHighlight fill:#f3e8ff,stroke:#8b5cf6,stroke-width:1.5px,color:#6b21a8;
    classDef greenHighlight fill:#dcfce7,stroke:#22c55e,stroke-width:1.5px,color:#166534;

    class A,D highlight;
    class C,E purpleHighlight;
    class G greenHighlight;
```

---

## 7. AI Agents State Diagram
Represents the step-by-step state machine lifecycle of the ViGil agent executor during payload threat forensics.

```mermaid
stateDiagram-v2
    [*] --> Initialization : File Uploaded
    Initialization --> Routing : Session ID & LTM Cache Checked
    Routing --> Extraction : Route = container
    Routing --> ML_Inference : Route = pe / script
    Extraction --> ML_Inference : Leaf files filtered
    ML_Inference --> Swarm_Startup : PyTorch output emitted
    
    state Swarm_Startup {
        [*] --> WebSocket_Started : Event 'agent_started' emitted
        WebSocket_Started --> Parallel_Analysis : Kickoff Crew thread
    }

    state Parallel_Analysis {
        [*] --> Running_Specialists
        Running_Specialists --> Structural_Done
        Running_Specialists --> Imports_Done
        Running_Specialists --> Network_Done
        Running_Specialists --> Evasion_Done
        Running_Specialists --> Strings_Done
        Structural_Done & Imports_Done & Network_Done & Evasion_Done & Strings_Done --> All_Specialists_Done
    }

    Swarm_Startup --> Parallel_Analysis
    Parallel_Analysis --> Results_Coordination : Trigger Coordinator
    Results_Coordination --> Consensus_Resolution : Trigger Comparator
    Consensus_Resolution --> Report_Compilation : Trigger Writer
    Report_Compilation --> SQLite_Storage : SQLite INSERT analysis & iocs
    SQLite_Storage --> Completion : Emit 'report_ready' WebSocket
    Completion --> [*] : Tab UI Rendered
```
