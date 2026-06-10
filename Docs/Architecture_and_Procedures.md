# ViGil — Quad-Modal Malware Detection: Architecture and Procedures Reference Document

This document provides a comprehensive technical overview of the **ViGil Quad-Modal Malware Detection framework**, detailing its deep learning architecture, its pipeline components, and the operational procedures for extraction, training, deployment, and prediction.

---

## 1. System Overview

ViGil is a state-of-the-art malware analysis and classification framework designed to handle extreme file format heterogeneity (executables, scripts, documents, installers, etc.) through a quad-modal fusion strategy. The framework extracts features across four distinct semantic modalities and fuses them using a **Deep Residual MLP** with **Monte Carlo (MC) dropout** for verdict confidence and epistemic uncertainty estimation.

```
                    ┌────────────────────────────────────────────────────────────┐
   File             │                 ViGil Quad-Modal Model                      │
   ──────►  CPG  ──►│  OptimizedHGT   (768-dim, JK+attn pool)                   │
          Image ──►│  ConvNeXt-Tiny  (512-dim)                                  ├──► DeepResMLP ──► BENIGN / MALWARE
          Bytes ──►│  AttentionByte  (256-dim)  ─ cross-modal ─►                │                + Confidence %
           APIs ──►│  CLSTransformer (256-dim)                                  │                + Uncertainty
                    └────────────────────────────────────────────────────────────┘
                              Fused: 768 + 512 + 256 = 1536-dim
```

---

## 2. Quad-Modal Deep Learning Architecture

The core of ViGil is a joint neural network model implemented in [uir/model/optimized_models.py](file:///Users/sasindumalhara/Workspace/ViGil/uir/model/optimized_models.py) (`JointMalwareModel`). It integrates four feature representation streams:

### A. Graph Stream (CPG & OptimizedHGT)
- **Data Source**: Code Property Graph (CPG) constructed from binary P-Code (Ghidra) or script Abstract Syntax Trees (AST).
- **Node Embeddings**: Every node in the CPG is vectorized into a **320-dimensional** feature vector (layout detailed in Section 3).
- **Encoder**: `OptimizedHGT` — an optimized **6-layer, 8-head Heterogeneous Graph Transformer** with:
  - Meta-relation type parameters (source type, edge type, target type).
  - Jumping Knowledge (JK) residual connections across layers.
  - Global attention pooling over the nodes to yield a graph embedding.
- **Output**: **768-dimensional** representation (`hidden_dim` * 2, where `hidden_dim` = 384).

### B. Image Stream (ConvNeXt-Tiny)
- **Data Source**: Grayscale byte-density image of size $224 \times 224 \times 3$.
- **Encoder**: `OptimizedCNN` — utilizes a `ConvNeXt-Tiny` backbone (pre-trained on ImageNet).
- **Output**: **512-dimensional** representation (`OUT_DIM` = 512).

### C. Raw Bytes & API Imports Stream (RansomFormer)
The raw bytes and API imports are processed via a dual-stream cross-modal encoder:
- **Raw Bytes**: $1 \times 1024$ window byte-density sequence parsed via `OptimizedByteEncoder` consisting of a 3-layer 1D CNN with max pooling and attention-based pooling. Output is 256-dim.
- **API Imports**: Tokenized sequence of 256 API IDs processed via `OptimizedAPIEncoder` using a 4-layer Pre-LN Transformer encoder with a local 1D CNN branch and a CLS token. Output is 256-dim.
- **Fusion Mechanism**: `OptimizedRansomFormerEncoder` — computes multi-head cross-attention where the byte sequence represents the Query ($Q$), and the API features represent the Key ($K$) and Value ($V$).
- **Output**: **256-dimensional** cross-modal representation.

### D. Fusion Head (Deep Residual MLP)
- **Encoder**: `OptimizedFusion` — receives the concatenated feature vector of shape **1536-dim** (768 HGT + 512 CNN + 256 RansomFormer).
- **Architecture**: A deep multilayer perceptron containing:
  - Dense linear projection to a hidden size of 1024, followed by GELU activation, LayerNorm, and 40% dropout.
  - Residual connection addition if sizes match.
  - Final classification head projecting to `num_classes = 2` (BENIGN vs. MALWARE).
- **Uncertainty Estimation**: Uses **Monte Carlo (MC) dropout** at inference time. Running $T$ passes with active dropout generates a distribution of probability predictions, allowing calculations of:
  - **Verdict**: The argmax of the mean class probabilities.
  - **Confidence**: The mean probability of the predicted class.
  - **Epistemic Uncertainty**: The variance of the predicted class probability across the Monte Carlo iterations.

---

## 3. Feature Engineering & Code Property Graphs

### CPG Schema definition
The CPG merges syntactic, control, and data-dependency structures to represent program logic.
1. **AST Edges (`IS_AST_PARENT`)**: Syntactic hierarchy (e.g., Methods containing Blocks containing Calls).
2. **CFG Edges (`FLOWS_TO`)**: Control flow execution paths (e.g., sequential, branch, loop).
3. **PDG Edges (`REACHES`, `CONTROLS`)**: Data dependency (variable write $\rightarrow$ variable read) and control dependency.

### 320-Dimensional Node Feature Layout
The dataset builder in [uir/model/dataset.py](file:///Users/sasindumalhara/Workspace/ViGil/uir/model/dataset.py) maps CPG nodes into vectors:

| Dimension Range | Feature Category | Description |
| :--- | :--- | :--- |
| `[0..10]` | Node Type | One-hot encoding of the node type (Method, Block, Call, Literal, Identifier, etc.). |
| `[11..13]` | Degree Centrality | Log-normalized in-degree, out-degree, and total degree. |
| `[14..21]` | Typed In-Degrees | In-degrees categorized by the 8 edge types. |
| `[22..29]` | Typed Out-Degrees | Out-degrees categorized by the 8 edge types. |
| `[30]` | External Flag | 1.0 if the node represents an external library API import, 0.0 otherwise. |
| `[31]` | Line Number | Normalized code line number. |
| `[32..99]` | Name n-grams | 68-dimensional multi-hashed character n-gram fingerprint for variable/function names. |
| `[100..131]` | Block composition | One-hot-like count of statement types (If, While, Load, Store) inside the basic block. |
| `[132]` | Cyclomatic Complexity | Cyclomatic complexity metric (applicable for METHOD nodes). |
| `[133]` | API Call Count | Total external calls invoked (applicable for METHOD nodes). |
| `[134]` | Total Instructions | Count of instructions contained (applicable for METHOD nodes). |
| `[135]` | Basic Block Count | Number of basic blocks in method (applicable for METHOD nodes). |
| `[136]` | Outgoing Calls | Count of outgoing method call edges. |
| `[137]` | Instruction Entropy | Shannon entropy of instruction type distribution (applicable for BLOCK nodes). |
| `[138]` | Jump Ratio | Ratio of branches and jumps to total instructions (applicable for BLOCK nodes). |
| `[139]` | Memory Access Ratio | Ratio of memory Load/Store operations to total instructions (applicable for BLOCK nodes). |
| `[140]` | Call Ratio | Ratio of calls to total instructions (applicable for BLOCK nodes). |
| `[141]` | Block Size | Normalized basic block instruction count (applicable for BLOCK nodes). |
| `[142..209]` | Suspicious API Match | 68-dimensional multi-hashed fingerprint if calling sensitive Windows APIs (e.g., VirtualAllocEx). |
| `[210..277]` | Global Import BoW | 68-dimensional global bag-of-words representation of all imports, broadcast to all nodes. |
| `[278]` | Architecture | x86 = 1.0, x64 = 0.67, ARM = 0.33, Unknown = 0.0. |
| `[279]` | Subsystem | Subsystem identifier (normalized Windows subsystem ID). |
| `[280]` | File Type | Normalized one-hot mapping for extensions (exe, dll, sys, elf, macho, so). |
| `[281]` | PE Timestamp | Log-normalized compiler timestamp. |
| `[282]` | Import Count | Log-normalized count of PE imports. |
| `[283]` | String Count | Log-normalized count of extracted strings. |
| `[284]` | Export Count | Log-normalized count of PE exports. |
| `[285..319]` | Reserved | Zeros reserved for future structural expansions. |

---

## 4. Pipeline Execution Workflow

The extraction and normalization pipeline is implemented sequentially:

```
Raw File 
  ├── 1. Identification (libmagic + TrID)
  ├── 2. Unpacking (RecursiveExtractor if Archive/Installer/Disk Image)
  └── Leaf Nodes (Binary / Script / Document / Shortcut)
        ├── 3. Feature Extraction & Lifting
        │     ├── Binaries   ──► disassembly + Ghidra P-Code CFG
        │     ├── Scripts    ──► parse Tree-sitter AST
        │     ├── Documents  ──► olevba macros + Shellcode carving
        │     └── Launchers  ──► LNK parsing ──► synthetic call graph
        └── 4. CPG Generation ──► Node vectorization (320-dim) ──► .feat.pt Bundle
```

1. **Identification**: Files are classified using MIME-types (`libmagic`) and signatures (`TrID`).
2. **Recursive Extraction**: Archives (`.zip`, `.rar`, `.7z`), disk images (`.iso`, `.img`), and installers (`.msi`, `.cab`) are traversed up to a depth of 5. Payne/relational tables of MSI configurations are dumped to extract custom install scripts.
3. **Domain-Specific Lifting**:
   - **Binaries**: Headless Ghidra decompiles machine code to register-neutral P-Code micro-instructions.
   - **Scripts**: Transpiled into Abstract Syntax Trees (ASTs). Obfuscated JS/PS1 are analyzed dynamically using emulators (e.g., `box-js`) to resolve payload code.
   - **Documents**: Macro scripts are extracted using `olevba`; high-entropy streams are emulated to capture hidden shellcode.
   - **Launchers**: Target paths and command argument vectors of LNK shortcuts are modeled synthetically.
4. **CPG Serialization**: Generates a unified JSON file, compiled into a PyTorch `.feat.pt` dataset bundle.

---

## 5. Procedures & Operational Guides

### Procedure A: Local Feature Extraction
Use the `uir` batch processor CLI to generate `.feat.pt` files locally. Choose a hardware acceleration profile to tune worker pools and memory mapping.

```bash
# Process malware samples
uir batch --input-dir ./dataset/malwares --output-dir ./features/malwares --device-profile m4

# Process benign samples
uir batch --input-dir ./dataset/benigns --output-dir ./features/benigns --device-profile m4
```

*Profile options (`--device-profile`)*:
- `m4`: Optimized for Apple Silicon unified memory mapping.
- `gtx_1650_ti`: Tailored for 4GB NVIDIA VRAM bounds.
- `cpu_default`: General multi-core CPU execution.

---

### Procedure B: Kaggle Model Training
Training is done exclusively on Kaggle GPU resources to support large batch HGT models.

1. **Zip Feature Bundles**:
   ```bash
   zip -r vigil_features.zip features/**/*.feat.pt
   ```
2. **Zip Project Source Code**:
   ```bash
   zip -r vigil_src.zip uir/ predict.py export_zip.py setup.py traning_notebook/
   ```
3. **Upload to Kaggle**:
   - Upload `vigil_features.zip` as a dataset named `vigil-features`.
   - Upload `vigil_src.zip` as a dataset named `vigil-src`.
4. **Run Notebook**:
   - Create a Kaggle Notebook and import `traning_notebook/vigil.ipynb`.
   - Add both datasets (`vigil-features`, `vigil-src`).
   - Enable **Accelerator: GPU T4 x2** (or P100) and **Internet** in settings.
   - Configure data directories in cell 1:
     ```python
     FEAT_DIR = Path('/kaggle/input/vigil-features')
     ```
   - Click **Run All**; training saves checkpoints under the outputs directory. Download the final `joint_model.pt` weights.

---

### Procedure C: Local Model Deployment
Deploy the trained weights into the local execution path for prediction:

```bash
# Place checkpoint in directory
mkdir -p models/01/models
mv joint_model.pt models/01/models/joint_model.pt

# Execute prediction
python predict.py --file suspicious.exe
```

---

### Procedure D: Run Inference
The standalone [predict.py](file:///Users/sasindumalhara/Workspace/ViGil/predict.py) script accepts binary, script, or document payloads:

```bash
# Standard prediction (verdict, confidence, and uncertainty stats)
python predict.py --file path/to/target.exe

# Customized Monte Carlo dropout sampling and verbose tracking
python predict.py --file path/to/target.dll --samples 30 --verbose

# Output predictions as raw JSON
python predict.py --file path/to/target.exe --json
```

---

### Procedure E: Packaging a Deployment ZIP
Export the active model checkpoint along with the standalone predictor and code dependencies to distribute ViGil:

```bash
python export_zip.py --checkpoint models/01/models/joint_model.pt --output vigil_deploy.zip
```
This builds a portable zip containing the required runtime module structure (`src/`), configuration specifications, weights, and `predict.py`.
