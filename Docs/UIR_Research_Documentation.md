# Unified Instruction Representation (UIR) for Heterogeneous Malware Analysis

## A Deep Learning Framework Using Code Property Graphs and Heterogeneous Graph Transformers

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Introduction & Motivation](#2-introduction--motivation)
3. [System Architecture Overview](#3-system-architecture-overview)
4. [Phase 1: Recursive Extraction Layer](#4-phase-1-recursive-extraction-layer)
5. [Phase 2: Domain-Specific Lifting](#5-phase-2-domain-specific-lifting)
6. [Phase 3: Code Property Graph Construction](#6-phase-3-code-property-graph-construction)
7. [Phase 4: Feature Engineering & Tokenization](#7-phase-4-feature-engineering--tokenization)
8. [Phase 5: Deep Learning Classification](#8-phase-5-deep-learning-classification)
9. [Training Methodology](#9-training-methodology)
10. [Hardware-Aware Pipeline Optimization](#10-hardware-aware-pipeline-optimization)
11. [Implementation Details](#11-implementation-details)
12. [Dataset Characterization](#12-dataset-characterization)
13. [Evaluation Metrics](#13-evaluation-metrics)
14. [Project Structure Reference](#14-project-structure-reference)
15. [References](#15-references)

---

## 1. Abstract

The **Unified Instruction Representation (UIR)** framework addresses the fundamental challenge of heterogeneous malware analysis — detecting malicious intent across diverse file formats using a single, unified deep learning model. Traditional approaches employ siloed models: CNNs for binary images, RNNs for scripts, and gradient boosting for PE headers. These fail to capture the **semantic equivalence** of malicious logic across different representations.

UIR solves this by constructing a **Code Property Graph (CPG)** — a graph-based intermediate representation that superimposes the Abstract Syntax Tree (AST), Control Flow Graph (CFG), and Program Dependence Graph (PDG) onto a unified node set. By lifting all file types (compiled binaries, interpreted scripts, documents, launchers) into this common graph schema, a single **Heterogeneous Graph Transformer (HGT)** model can detect malicious behavior regardless of the delivery mechanism.

The framework processes a dataset of **55,271 files across 53 distinct extensions**, spanning native binaries (.exe, .elf, .dll), scripts (.js, .ps1, .vbs), documents (.doc, .pdf, .xlsm), archives (.zip, .iso, .msi), and launchers (.lnk, .url).

---

## 2. Introduction & Motivation

### 2.1 The Semantic Gap Problem

Modern malware campaigns leverage a diverse ecosystem of file formats. A "downloader" routine functions identically whether implemented in x86 assembly, PowerShell, or a VBA macro, yet traditional siloed approaches treat these as fundamentally different phenomena.

| Traditional Approach | Limitation |
|:---|:---|
| CNN on raw bytes | Learns PE header patterns (MZ, PE\0\0), fails on ASCII scripts |
| RNN/BERT on source code | Excellent for sequential tokens, struggles with non-linear control flow in binaries |
| GNN on graphs | Requires graph input, cannot handle raw text or byte streams |

### 2.2 The CPG Solution

The **Code Property Graph** bridges this gap by normalizing *all* input types into a graph representation:

- A **loop in assembly** becomes a cyclic subgraph in the CPG
- A **loop in Python** becomes a cyclic subgraph in the CPG
- The deep learning model learns the **concept of "looping behavior"** independent of source language

This unification enables **cross-format transfer learning**: a buffer overflow pattern learned from x86 binaries can be detected in ARM IoT malware because the CPG graph structure remains topologically identical.

---

## 3. System Architecture Overview

The UIR system operates as a **four-phase pipeline**, transforming raw heterogeneous files into a unified graph representation for deep learning classification.

![UIR End-to-End Pipeline Architecture](/Users/sasindumalhara/.gemini/antigravity/brain/1acc066f-ecc5-4a45-8adc-4550da975412/pipeline_architecture_light_1773673149254.png)

### High-Level Data Flow

```
Raw Files (53 formats)
    │
    ▼
┌────────────────────────┐
│  Phase 1: EXTRACTION   │  File identification, recursive unpacking,
│  (Recursive Engine)    │  polyglot detection, deduplication
└──────────┬─────────────┘
           │ Leaf Files
           ▼
┌────────────────────────┐
│  Phase 2: LIFTING      │  Domain-specific code analysis:
│  (Binary/Script/Doc/   │  PE→P-Code, Script→AST, Doc→VBA,
│   Launcher Lifters)    │  LNK→Synthetic Call Graph
└──────────┬─────────────┘
           │ Lifted Representation
           ▼
┌────────────────────────┐
│  Phase 3: CPG BUILD    │  Construct unified Code Property Graph:
│  (Builder + Schema)    │  AST + CFG + PDG edges on shared nodes
└──────────┬─────────────┘
           │ Code Property Graph
           ▼
┌────────────────────────┐
│  Phase 4: TOKENIZE     │  Semantic vocabulary + BPE + Value
│  + EMBED + CLASSIFY    │  Abstraction → HGT → Malware/Benign
└────────────────────────┘
```

---

## 4. Phase 1: Recursive Extraction Layer

### 4.1 Architecture

The extraction layer handles the first critical challenge: modern malware is rarely distributed as naked executables. Threats are encapsulated in layers of archives, disk images, and installers. The extraction layer recursively unpacks these containers to expose the underlying executable logic.

#### Core Components

| Component | Module | Responsibility |
|:---|:---|:---|
| **File Identifier** | [extraction/file_identifier.py](file:///Volumes/MALHARA/CPG/uir/extraction/file_identifier.py) | Content-based file type identification using magic bytes + extensions |
| **Recursive Engine** | [extraction/recursive_engine.py](file:///Volumes/MALHARA/CPG/uir/extraction/recursive_engine.py) | BFS-based recursive unpacking with depth limiting and deduplication |
| **Archive Extractor** | [extraction/archive_extractor.py](file:///Volumes/MALHARA/CPG/uir/extraction/archive_extractor.py) | ZIP, RAR, 7z, TAR, GZ, CAB extraction |
| **Disk Image Extractor** | [extraction/disk_image_extractor.py](file:///Volumes/MALHARA/CPG/uir/extraction/disk_image_extractor.py) | ISO (via pycdlib), IMG, VHD parsing |
| **MSI Extractor** | [extraction/msi_extractor.py](file:///Volumes/MALHARA/CPG/uir/extraction/msi_extractor.py) | Windows Installer database + CustomAction script extraction |

### 4.2 File Identification Strategy

The system prioritizes **content-based detection** over extension-based detection to defeat extension spoofing, a common malware evasion technique.

```
┌─────────────────────────────────────────────────────┐
│                File Identification                   │
│                                                      │
│  1. Read first 32 bytes (magic header)              │
│  2. Match against MAGIC_SIGNATURES table            │
│     ├─ b'MZ'           → PE Executable              │
│     ├─ b'\x7fELF'      → ELF Binary                │
│     ├─ b'\xfe\xed...'  → Mach-O                    │
│     ├─ b'PK\x03\x04'   → ZIP-based (JAR/APK/DOCX) │
│     ├─ b'Rar!\x1a\x07' → RAR Archive               │
│     ├─ b'\xd0\xcf...'  → OLE Compound Document     │
│     ├─ b'%PDF'         → PDF Document               │
│     └─ b'\x4c\x00...'  → LNK Shortcut              │
│                                                      │
│  3. Refine PE types (EXE vs DLL vs SYS via pefile)  │
│  4. Refine ZIP types (JAR vs APK vs DOCX via        │
│     internal structure inspection)                   │
│  5. Refine OLE types (DOC vs XLS vs MSI via         │
│     OLE stream names)                               │
│  6. Polyglot detection if magic ≠ extension         │
└─────────────────────────────────────────────────────┘
```

### 4.3 Recursive Extraction Engine

The engine operates as a **breadth-first queue** with safety controls:

- **Depth limiting** (default: 5 levels) prevents zip bomb attacks
- **File count limiting** (default: 1000 files) prevents resource exhaustion
- **SHA-256 deduplication** eliminates duplicate payloads across nested layers
- **Path traversal protection** prevents [../../../etc/passwd](file:///etc/passwd) escape attacks

```python
# Pseudocode for recursive extraction
queue = [(input_file, depth=0)]
while queue:
    file, depth = queue.pop()
    if depth > MAX_DEPTH: skip
    
    identify(file)  # Content-based type detection
    hash = SHA256(file)
    if hash in seen_hashes: skip  # Deduplication
    
    if is_container(file):
        children = extract(file)  # Archive/ISO/MSI extraction
        queue.extend([(c, depth+1) for c in children])
    else:
        yield file  # Leaf file → forward to lifting
```

### 4.4 Specialized Extractors

**Archive Extractor**: Handles ZIP, RAR (via `rarfile`), 7z (via `py7zr`), TAR, GZ, and CAB formats with path traversal protection on every extracted member.

**Disk Image Extractor**: Parses ISO 9660/UDF filesystems via `pycdlib` without mounting, supporting Joliet and Rock Ridge extensions for long filenames. This is critical for analyzing Qakbot/Bumblebee campaigns that abuse ISO images to bypass Windows Mark-of-the-Web controls.

**MSI Extractor**: Treats MSI files as OLE compound documents, extracting both binary payloads from internal CAB streams and embedded scripts from CustomAction tables — a common vector for VBScript/JScript execution during installation.

---

## 5. Phase 2: Domain-Specific Lifting

### 5.1 The Lifting Abstraction

The lifting layer converts diverse file formats into a **unified intermediate representation** ([LiftedRepresentation](file:///Volumes/MALHARA/CPG/uir/lifting/base_lifter.py#110-140)) that captures:

- **Functions/Methods**: Named code blocks with entry points
- **Basic Blocks**: Sequences of instructions with single entry/exit
- **Instructions**: Normalized operations with typed operands
- **Control Flow**: Block successor/predecessor relationships
- **Data Dependencies**: Variable definition-use chains

All lifters implement a common [BaseLifter](file:///Volumes/MALHARA/CPG/uir/lifting/base_lifter.py#142-179) abstract interface:

```python
class BaseLifter(ABC):
    @abstractmethod
    def can_lift(self, file_type: FileType) -> bool: ...
    
    @abstractmethod
    def lift(self, file_path: Path) -> LiftedRepresentation: ...
```

A [LifterRegistry](file:///Volumes/MALHARA/CPG/uir/lifting/base_lifter.py#181-204) dispatches files to the appropriate lifter based on file type.

### 5.2 Binary Lifter (PE / ELF / Mach-O)

**Module**: [lifting/binary_lifter.py](file:///Volumes/MALHARA/CPG/uir/lifting/binary_lifter.py)  
**Supports**: EXE, DLL, SYS, SCR, CPL, ELF, SO, Mach-O

The binary lifter is the most complex component, handling ~49,000 files across multiple CPU architectures (x86, x64, ARM, ARM64).

#### P-Code Lifting Strategy

The system targets **Ghidra P-Code** as the unifying intermediate representation. P-Code is a Register Transfer Language (RTL) that abstracts complex CISC instructions into simple micro-operations:

| x86 Instruction | P-Code Equivalent |
|:---|:---|
| `POP EAX` | `LOAD (stack) → EAX; INT_ADD ESP, 4 → ESP` |
| `ADD EAX, EBX` | `INT_ADD EAX, EBX → EAX` |
| `JNZ label` | `CBRANCH cond, label` |

**P-Code to InstructionType mapping** (26 operations):

```
INT_ADD → ADD    |  INT_AND → AND    |  INT_EQUAL → EQ
INT_SUB → SUB    |  INT_OR  → OR     |  INT_LESS  → LT
INT_MULT → MUL   |  INT_XOR → XOR    |  LOAD      → LOAD
INT_DIV → DIV    |  INT_NOT → NOT    |  STORE     → STORE
BRANCH  → BRANCH |  CBRANCH → CBRANCH|  CALL      → CALL
RETURN  → RETURN |  COPY    → COPY   |  CAST      → CAST
```

#### PE Analysis Pipeline

```
PE File Input
    │
    ├── pefile parsing (fast_load=False)
    │   ├── Import Table → External CALL nodes
    │   ├── Export Table → Exported functions
    │   ├── Entry Point → Main function
    │   ├── Architecture detection (x86/x64/ARM)
    │   └── Characteristics (DLL/SYS/EXE)
    │
    ├── Code Section Analysis
    │   ├── Accelerated Pattern Scanner (numpy-vectorized)
    │   │   ├── E8 → CALL (relative)
    │   │   ├── C3 → RETURN
    │   │   ├── E9 → BRANCH (near jump)
    │   │   └── EB → BRANCH (short jump)
    │   └── Sequential fallback
    │
    ├── String Extraction
    │   ├── Accelerated (numpy-vectorized ASCII + UTF-16 LE)
    │   └── Sequential fallback
    │
    └── Optional: Ghidra P-Code lifting (headless analysis)
```

### 5.3 Script Lifter (JS / PY / PS1 / VBS / BAT / SH)

**Module**: [lifting/script_lifter.py](file:///Volumes/MALHARA/CPG/uir/lifting/script_lifter.py)  
**Supports**: 15 scripting languages

The script lifter handles text-based interpreted code with a focus on two key challenges: **obfuscation detection** and **cross-language normalization**.

#### Obfuscation Detection

Before lifting, each script is analyzed for obfuscation indicators:

| Pattern | Indicator |
|:---|:---|
| [eval()](file:///Volumes/MALHARA/CPG/uir/model/trainer.py#148-189), [exec()](file:///Volumes/MALHARA/CPG/uir/extraction/file_identifier.py#378-387), `Invoke-Expression` | Dynamic code execution |
| Base64 strings (40+ chars matching `[A-Za-z0-9+/]{40,}`) | Encoded payloads |
| `FromBase64String` | .NET base64 decoding |

#### Language-Specific Lifting

| Language | Parser | Functions | Control Flow |
|:---|:---|:---|:---|
| **Python** | `ast.parse()` (stdlib) | `FunctionDef` nodes | AST walk |
| **JavaScript** | Regex-based | `function name()` patterns | Function call detection |
| **PowerShell** | Pattern matching | `function Name` | Cmdlet detection (`Get-*`, `Invoke-*`) |
| **VBScript** | Pattern matching | `Sub`/[Function](file:///Volumes/MALHARA/CPG/uir/lifting/base_lifter.py#93-108) declarations | N/A |
| **Batch/CMD** | Line-by-line | N/A | [call](file:///Volumes/MALHARA/CPG/uir/cpg/graph.py#110-113), `start`, [cmd](file:///Volumes/MALHARA/CPG/uir/pipeline/cli.py#124-213), [powershell](file:///Volumes/MALHARA/CPG/uir/lifting/script_lifter.py#122-134) |
| **Shell** | Pattern matching | [name() {](file:///Volumes/MALHARA/CPG/uir/tokenization/embedding.py#147-164) patterns | N/A |

### 5.4 Document Lifter (DOC / PDF / RTF)

**Module**: [lifting/document_lifter.py](file:///Volumes/MALHARA/CPG/uir/lifting/document_lifter.py)  
**Supports**: 12 document formats

Documents are containers that *embed* code. The lifter extracts this embedded logic:

#### OLE Documents (DOC, XLS, PPT, DOCM, XLSM)

Uses **oletools** (`olevba`) to:
1. Detect VBA macros (`detect_vba_macros()`)
2. Extract macro source code (`extract_macros()`)
3. Parse VBA functions and subroutines
4. Detect suspicious API patterns: `Shell`, `CreateObject`, `WScript.Shell`, `URLDownloadToFile`
5. Identify auto-execution hooks: `AutoOpen`, `Document_Open`, `Workbook_Open`

#### OOXML Documents (DOCX, XLSX, PPTX)

Inspects ZIP internal structure for:
- `vbaProject.bin` → Extracts and analyzes via OLE pipeline
- External relationships in `.rels` files → Detects template injection

#### PDF Analysis

- Scans for `/JavaScript`, `/JS` streams
- Detects suspicious actions: `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`
- **Shannon entropy analysis** for shellcode detection (threshold: 7.5)

#### RTF Analysis

- Detects embedded OLE objects (`\object`, `objdata`)
- Identifies Equation Editor exploit patterns (`Equation.`, `0002CE02`)

### 5.5 Launcher Lifter (LNK / URL / .desktop)

**Module**: [lifting/launcher_lifter.py](file:///Volumes/MALHARA/CPG/uir/lifting/launcher_lifter.py)  
**Supports**: LNK, URL, .desktop files

Launchers define execution intent. The lifter constructs **synthetic call graphs**:

```
LNK File: target=cmd.exe, args="/c powershell -enc <payload>"

Synthetic CPG:
  LNK_Main (METHOD)
    └── BasicBlock
        ├── CALL cmd.exe       → flagged: "Command execution"
        ├── CALL powershell    → flagged: "PowerShell execution"
        └── CALL -enc          → flagged: "Encoded command"
```

**Living-off-the-Land (LotL) Detection**: Recognizes 8 suspicious argument patterns:
[powershell](file:///Volumes/MALHARA/CPG/uir/lifting/script_lifter.py#122-134), `-enc`, `cmd /c`, `mshta`, `regsvr32`, `rundll32`, `certutil`, `bitsadmin`

---

## 6. Phase 3: Code Property Graph Construction

### 6.1 The CPG Schema

![Code Property Graph Schema](/Users/sasindumalhara/.gemini/antigravity/brain/1acc066f-ecc5-4a45-8adc-4550da975412/cpg_schema_diagram_light_1773673170249.png)

The CPG is a **directed, attributed multigraph** G = (V, E, μ, ν) implementing the Joern CPG specification with the following schema:

#### Node Types (10 types)

| Node Type | Role | Key Attributes |
|:---|:---|:---|
| **METHOD** | Function/subroutine | [name](file:///Volumes/MALHARA/CPG/uir/tokenization/embedding.py#147-164), `signature`, `is_external` |
| **BLOCK** | Basic block | `start_address`, `end_address` |
| **CALL** | Function invocation | [name](file:///Volumes/MALHARA/CPG/uir/tokenization/embedding.py#147-164), `dispatch_type` |
| **OPERATOR** | Algebraic/logical operation | `operator_type` (normalized to `<operator>.addition`, etc.) |
| **CONTROL_STRUCTURE** | If/While/For/Try | `control_type` (IF, WHILE, FOR, TRY, etc.) |
| **RETURN** | Return statement | [code](file:///Volumes/MALHARA/CPG/uir/tokenization/bpe_tokenizer.py#149-155) |
| **IDENTIFIER** | Variable/register reference | [name](file:///Volumes/MALHARA/CPG/uir/tokenization/embedding.py#147-164) |
| **LITERAL** | Constant value | [value](file:///Volumes/MALHARA/CPG/uir/tokenization/value_abstractor.py#146-149), `value_type` |
| **PARAMETER** | Function parameter | [name](file:///Volumes/MALHARA/CPG/uir/tokenization/embedding.py#147-164), `order` |
| **LOCAL** | Local variable | [name](file:///Volumes/MALHARA/CPG/uir/tokenization/embedding.py#147-164) |

#### Edge Types (8 types)

| Edge Type | Graph Layer | Semantics |
|:---|:---|:---|
| **IS_AST_PARENT** | AST | Syntactic containment (METHOD → BLOCK → CALL) |
| **FLOWS_TO** | CFG | Execution order (Instruction A → Instruction B) |
| **REACHES** | PDG (Data) | Data dependency (var defined → var used) |
| **CONTROLS** | PDG (Control) | Control dependency |
| **CALLS** | Call Graph | Function invocation |
| **CALLED_BY** | Call Graph | Reverse of CALLS |
| **ARGUMENT** | AST | Instruction → operand |
| **RECEIVER** | AST | Method invocation target |

#### Semantic Normalization via Operators

The key insight enabling cross-format learning: operations from all languages are normalized to a common set of `<operator>` types:

| Source | Original Syntax | Normalized CPG Operator |
|:---|:---|:---|
| x86 Assembly | `ADD EAX, EBX` | `<operator>.addition` |
| JavaScript | `x + y` | `<operator>.addition` |
| Python | `a + b` | `<operator>.addition` |
| P-Code | `INT_ADD` | `<operator>.addition` |

This enables the neural network to learn the **concept of addition** rather than the specific syntax.

### 6.2 CPG Builder

**Module**: [cpg/builder.py](file:///Volumes/MALHARA/CPG/uir/cpg/builder.py)

The builder transforms [LiftedRepresentation](file:///Volumes/MALHARA/CPG/uir/lifting/base_lifter.py#110-140) → [CodePropertyGraph](file:///Volumes/MALHARA/CPG/uir/cpg/graph.py#16-334):

```
For each Function:
    1. Create METHOD node
    2. For each BasicBlock:
        a. Create BLOCK node
        b. Add AST edge: METHOD → BLOCK
        c. Add CFG edge: Previous BLOCK → Current BLOCK
        d. For each Instruction:
            i.   Create appropriate node (CALL/OPERATOR/CONTROL_STRUCTURE/RETURN)
            ii.  Add AST edge: BLOCK → Instruction
            iii. Add CFG edge: Previous Instruction → Current Instruction
            iv.  For each Operand:
                 - Create LITERAL or IDENTIFIER node
                 - Add ARGUMENT edge: Instruction → Operand
                 - Add DATA_FLOW edge if operand is output
    3. Add CFG edges for block successor relationships
    4. Add CALLS edges between METHOD nodes
```

### 6.3 Graph Data Structure

**Module**: [cpg/graph.py](file:///Volumes/MALHARA/CPG/uir/cpg/graph.py)

The [CodePropertyGraph](file:///Volumes/MALHARA/CPG/uir/cpg/graph.py#16-334) class provides:

- **Indexed lookups**: O(1) node access by ID, O(1) edges by source/target via adjacency lists
- **Type-indexed queries**: Fast retrieval of all nodes of a given type
- **Graph traversal**: BFS and DFS with optional edge-type filtering
- **Merge operations**: Combine multiple CPGs (for container files) with ID offset remapping
- **Subgraph extraction**: Extract connected components for analysis
- **Optimized serialization**: orjson (10-50x faster than stdlib) or msgpack (compact binary)

---

## 7. Phase 4: Feature Engineering & Tokenization

### 7.1 Hybrid Tokenization Strategy

![Lifting and Tokenization Architecture](/Users/sasindumalhara/.gemini/antigravity/brain/1acc066f-ecc5-4a45-8adc-4550da975412/lifting_tokenization_light_1773673197209.png)

The tokenization layer solves the **Out-Of-Vocabulary (OOV) problem**: malware binaries contain millions of unique literals (memory addresses, randomized strings, large constants). A standard vocabulary would be infinitely large and sparse.

#### 7.1.1 Semantic Vocabulary (Fixed)

**Module**: [tokenization/vocabulary.py](file:///Volumes/MALHARA/CPG/uir/tokenization/vocabulary.py)

A fixed vocabulary of ~300 tokens covering the structural elements of the CPG:

| Category | Examples | Count |
|:---|:---|:---|
| Special tokens | `<PAD>`, `<UNK>`, `<LARGE_INT>`, `<MEM_ADDR>`, `<STRING>` | 5 |
| Operators | `<op>.ADD`, `<op>.CALL`, `<op>.BRANCH`, ... | 28 |
| Node types | `<node>.METHOD`, `<node>.CALL`, `<node>.LITERAL`, ... | 10 |
| Control structures | `<ctrl>.IF`, `<ctrl>.WHILE`, `<ctrl>.TRY`, ... | 9 |
| Registers | `<reg>.REG_GEN`, `<reg>.REG_SP`, `<reg>.REG_EAX`, ... | 18 |
| API categories | `<api>.FILE`, `<api>.NETWORK`, `<api>.PROCESS`, ... | 11 |
| Value types | `<type>.INT`, `<type>.STRING`, `<type>.PTR`, ... | 7 |
| Small integers | `<int>.-100` to `<int>.100` | 201 |
| Magic values | `<magic>.0x4D5A` (MZ), `<magic>.0x90` (NOP), ... | 9 |

#### 7.1.2 BPE Tokenizer for Identifiers

**Module**: [tokenization/bpe_tokenizer.py](file:///Volumes/MALHARA/CPG/uir/tokenization/bpe_tokenizer.py)

For user-defined strings (variable names, function names), **Byte-Pair Encoding** handles unseen identifiers by breaking them into known sub-components:

```
DownloadAndExecute → [download, and, execute]
URLDownloadToFileA → [url, download, to, file, a]
```

The BPE tokenizer:
1. Splits identifiers on `_` (snake_case) and camelCase boundaries
2. Applies iterative merge operations learned from a training corpus
3. Falls back to character-level tokenization for unknown subwords

#### 7.1.3 Value Abstraction

**Module**: [tokenization/value_abstractor.py](file:///Volumes/MALHARA/CPG/uir/tokenization/value_abstractor.py)

Large integers and memory addresses are normalized:

| Value Type | Example | Token |
|:---|:---|:---|
| Small integer (-1000 to 1000) | `42` | `<INT_42>` |
| Magic number | `0x4D5A` | `<MAGIC_0x4d5a>` |
| Memory address (32-bit) | `0x00401000` | `<MEM_ADDR>` |
| Memory address (64-bit) | `0x7FF...` | `<MEM_ADDR>` |
| Large integer | `1000000` | `<LARGE_INT>` |
| URL | `http://evil.com` | `<URL>` |
| File path | `C:\Windows\...` | `<PATH>` |
| IP address | `192.168.1.1` | `<IP_ADDR>` |
| Base64 string | `TWFsd2FyZQ==` | `<BASE64>` |

### 7.2 Embedding Layer

**Module**: [tokenization/embedding.py](file:///Volumes/MALHARA/CPG/uir/tokenization/embedding.py)

The [EmbeddingLayer](file:///Volumes/MALHARA/CPG/uir/tokenization/embedding.py#20-168) (nn.Module) creates dense vector representations for CPG nodes by combining three embedding sources:

```
Node → [Node Type Embedding ⊕ Semantic Vocabulary Embedding] + [BPE Name Embedding]
        ↓ Linear projection                                    ↓ Linear projection
        ↓                                                      ↓
        └──────────────── Concatenate ──────────────────────────┘
                              ↓
                    Linear(3/2 * dim → dim)
                              ↓
                        LayerNorm
                              ↓
                  Node Feature Vector (256-dim)
```

---

## 8. Phase 5: Deep Learning Classification

### 8.1 Heterogeneous Graph Transformer (HGT)

**Module**: [model/hgt.py](file:///Volumes/MALHARA/CPG/uir/model/hgt.py)

The HGT is chosen over standard Graph Convolutional Networks (GCNs) because the CPG contains **heterogeneous** nodes and edges. A METHOD node is fundamentally different from a LITERAL node, and a FLOWS_TO edge implies a different relationship than a REACHES edge.

#### Why HGT Over GCN?

| Feature | Standard GCN | HGT (Used) |
|:---|:---|:---|
| Node types | Single type assumed | **10 distinct types** with separate projections |
| Edge types | Single type assumed | **8 distinct types** with separate attention |
| Attention | Uniform | **Meta-relation aware** (Source Type → Edge Type → Target Type) |
| Expressiveness | Limited heterogeneity | Learns type-specific message passing |

#### Model Architecture (High-Level)

```
Input: Node Features (N × 256)
    ↓
Input Projection (Linear: 256 → 256)
    ↓
HGT Convolution Layer ×4
    ├── Per-type Q, K, V projections (10 node types)
    ├── Per-type attention weights (8 edge types)
    ├── Per-type message transforms (8 edge types)
    ├── Attention-weighted message aggregation
    ├── Output projection + Skip connection
    └── LayerNorm
    ↓
Attention-based Graph Pooling
    ├── Gate: σ(Linear(x)) → per-node importance
    ├── Weighted aggregation per graph
    └── Normalize by node count
    ↓
Classification Head
    ├── Linear(256 → 256) + ReLU + Dropout
    └── Linear(256 → 2)
    ↓
Output: [P(benign), P(malware)]
```

#### Model Configuration

| Hyperparameter | Value |
|:---|:---|
| Input dimension | 256 |
| Hidden dimension | 256 |
| Number of attention heads | 8 |
| Number of HGT layers | 4 |
| Head dimension | 32 (256 / 8) |
| Number of node types | 10 |
| Number of edge types | 8 |
| Dropout | 0.1 |
| Output classes | 2 (benign / malware) |

### 8.2 HGT Convolution Layer Detail

Each HGT layer computes updated node representations through **meta-relation aware attention**:

```
For each node type t:
    Q[nodes_of_type_t] = W_q^t × X[nodes_of_type_t]
    K[nodes_of_type_t] = W_k^t × X[nodes_of_type_t]
    V[nodes_of_type_t] = W_v^t × X[nodes_of_type_t]

For each edge type e:
    For each edge (source → target) of type e:
        α = softmax(Q[target] · A^e(K[source]) / √d)   # Attention score
        msg = M^e(V[source]) × α                         # Weighted message
        
    Aggregate messages: out[target] += Σ msg

Output = LayerNorm(W_out × out + X)  # Skip connection
```

> [!IMPORTANT]
> The key innovation is that **different edge types learn different attention patterns**. For example, the model might learn that `REACHES` edges (data dependencies) are highly important for detecting downloaders, while `FLOWS_TO` edges (control flow) are more relevant for detecting ransomware encryption loops.

---

## 9. Training Methodology

### 9.1 Loss Function: Combined Cross-Entropy + Contrastive

**Module**: [model/trainer.py](file:///Volumes/MALHARA/CPG/uir/model/trainer.py)

The training objective combines two loss functions:

```
L_total = L_CE + 0.5 × L_contrastive
```

#### Cross-Entropy Loss

Standard classification loss for malware vs. benign:

```
L_CE = -Σ [y × log(ŷ) + (1-y) × log(1-ŷ)]
```

#### Supervised Contrastive Loss

Forces the model to learn **invariant features** of malicious behavior:

```
L_contrastive = -Σ_i  (1/|P(i)|) × Σ_{p∈P(i)} log[exp(z_i · z_p / τ) / Σ_a exp(z_i · z_a / τ)]
```

Where:
- `z_i` = L2-normalized graph embedding of sample i
- [P(i)](file:///Volumes/MALHARA/CPG/uir/cpg/schema.py#194-222) = set of positive pairs (same class as i)
- `τ = 0.07` (temperature parameter)

This ensures:
- **Same-family** malware samples have similar embeddings (even if compiled differently)
- **Malware vs. benign** samples are maximally separated in the embedding space

### 9.2 Training Configuration

| Parameter | Value |
|:---|:---|
| Optimizer | AdamW (weight_decay=0.01) |
| Learning rate | 1e-4 |
| Batch size | 32 |
| Maximum epochs | 100 |
| Early stopping patience | 10 epochs |
| Gradient clipping | max_norm=1.0 |
| Train/Val split | 80/20 stratified |
| Contrastive temperature | 0.07 |

### 9.3 Data Loading & Batching

**Module**: [model/dataset.py](file:///Volumes/MALHARA/CPG/uir/model/dataset.py)

The [CPGDataset](file:///Volumes/MALHARA/CPG/uir/model/dataset.py#52-201) loads CPG JSON files and converts them to tensor format:

1. **Node features**: One-hot encoded node type + external flag + normalized line number + hashed name
2. **Edge indices**: COO format (2 × num_edges) tensor
3. **Node/Edge type IDs**: Integer tensors for HGT's type-aware attention
4. **Label inference**: Inferred from directory structure (`malware/` → 1, `benign/` → 0)

**Batch collation** combines multiple graphs into a single disconnected mega-graph with a batch assignment tensor, enabling efficient parallel processing.

---

## 10. Hardware-Aware Pipeline Optimization

### 10.1 Hardware Detection

**Module**: [pipeline/accelerator.py](file:///Volumes/MALHARA/CPG/uir/pipeline/accelerator.py)

The system auto-detects hardware and selects optimal processing strategies:

| Profile | Detection | Workers | Batch Size | Serialization |
|:---|:---|:---|:---|:---|
| **Apple M4** | ARM macOS + `sysctl` chip string | 6 (4P + 6E aware) | 100 (unified memory) | msgpack (compact) |
| **NVIDIA GTX 1650 Ti** | `torch.cuda.is_available()` | 8 (I/O bound) | 64 (keep CUDA fed) | orjson (fastest JSON) |
| **CPU Default** | Fallback | cpu_count - 1 | 50 (conservative) | orjson or stdlib json |

### 10.2 Accelerated Processing

#### Numpy-Vectorized String Extraction

Replaces O(n) Python byte-by-byte loops with vectorized numpy operations for **16-50x speedup**:

```python
# Traditional: ~1 byte/iteration in Python
for byte in data:
    if 32 <= byte < 127: current.append(chr(byte))

# Accelerated: vectorized boolean mask
arr = np.frombuffer(data, dtype=np.uint8)
printable = (arr >= 32) & (arr < 127)  # Vectorized!
```

Optional CuPy acceleration on NVIDIA GPUs moves the computation to CUDA.

#### Numpy-Vectorized Pattern Scanning

Binary code section analysis uses `np.where()` for batch opcode detection:

```python
# Find ALL call instructions in one vectorized operation
call_positions = np.where(arr == 0xE8)[0]
ret_positions = np.where(arr == 0xC3)[0]
jmp_positions = np.where(arr == 0xE9)[0]
```

### 10.3 Batch Processing Pipeline

**Module**: [pipeline/batch_processor.py](file:///Volumes/MALHARA/CPG/uir/pipeline/batch_processor.py)

The [BatchProcessor](file:///Volumes/MALHARA/CPG/uir/pipeline/batch_processor.py#89-416) uses `ProcessPoolExecutor` with hardware-optimized worker counts:

- **M4 optimization**: Larger batch windows (100 files) exploit unified memory — no data copy overhead between processes
- **GTX optimization**: More workers (8) because I/O is the bottleneck, not compute
- **Default**: Standard multiprocessing with progress bars

---

## 11. Implementation Details

### 11.1 Configuration Management

**Module**: [uir/config.py](file:///Volumes/MALHARA/CPG/uir/config.py)

The system uses **Pydantic models** for validated, hierarchical configuration:

```
UIRConfig
├── ExtractionConfig
│   ├── max_recursion_depth: 5
│   ├── max_extracted_files: 1000
│   ├── enable_polyglot_detection: True
│   └── timeout_seconds: 300
├── LiftingConfig
│   ├── ghidra_path: Optional
│   ├── enable_pcode_lifting: True
│   ├── max_functions_per_binary: 10000
│   └── enable_library_dedup: True
├── CPGConfig
│   ├── include_ast_edges: True
│   ├── include_cfg_edges: True
│   ├── include_data_flow_edges: True
│   └── max_nodes_per_graph: 50000
├── CPGBuildConfig
│   ├── device_profile: AUTO
│   ├── use_fast_serialization: True
│   └── gpu_memory_limit_mb: 3072
├── TokenizationConfig
│   ├── vocab_size: 32000
│   ├── bpe_vocab_size: 8000
│   └── embedding_dim: 256
├── ModelConfig
│   ├── hidden_dim: 256
│   ├── num_heads: 8
│   ├── num_layers: 4
│   └── num_classes: 2
└── TrainingConfig
    ├── batch_size: 32
    ├── learning_rate: 1e-4
    ├── num_epochs: 100
    ├── early_stopping_patience: 10
    ├── use_contrastive_loss: True
    └── contrastive_temperature: 0.07
```

### 11.2 Command-Line Interface

**Module**: [pipeline/cli.py](file:///Volumes/MALHARA/CPG/uir/pipeline/cli.py)

The CLI provides four commands:

```bash
# Process a single file → CPG
uir process --input file.exe --output file.cpg.json --verbose

# Batch process directory → CPG collection
uir batch --input-dir ./malware_dataset --output-dir ./cpgs --device-profile m4

# Train HGT model on CPGs
uir train --data-dir ./cpgs --epochs 50 --test

# Run prediction on a file
uir predict --model ./checkpoints/best_model.pt --input suspicious.exe
```

### 11.3 CPG Persistence

The CPG supports three serialization backends:

| Backend | Speed | Size | Best For |
|:---|:---|:---|:---|
| `orjson` | 10-50x faster than stdlib | Standard JSON | GPU/CPU systems |
| `msgpack` | Fast, compact | ~40% smaller than JSON | Apple M4 (unified memory) |
| `json` (stdlib) | Baseline | Standard JSON | Universal fallback |

---

## 12. Dataset Characterization

### 12.1 Dataset Composition

The research dataset comprises **55,271 files across 53 distinct extensions**:

| Category | Extensions | ~Count | Semantic Characteristics |
|:---|:---|:---|:---|
| **Native Binaries** | .exe, .elf, .dll, .sys, .macho, .so, .scr, .cpl | ~49,000 | Direct CPU execution; machine instructions |
| **Managed Code** | .jar, .class, .apk, .dex | ~620 | VM-based execution (JVM, Dalvik) |
| **Scripts** | .js, .vbs, .ps1, .bat, .sh, .py, .pl, .lua, .php, .hta, .wsf, .cmd, .au3, .jse, .vbe | ~4,500 | Interpreted execution; high-level text |
| **Office/OLE** | .doc, .docx, .xls, .xlsx, .xlsm, .ppam, .ppt, .pptx, .docm, .xll | ~2,500 | Compound documents with embedded VBA macros |
| **Rich Documents** | .pdf, .rtf | ~185 | Embedded JS, actions, or shellcode |
| **Archives** | .zip, .7z, .rar, .gz, .tar, .iso, .img, .cab | ~3,000 | Containers concealing payloads |
| **Installers** | .msi, .dmg | ~470 | Database-driven execution with CustomAction scripts |
| **Launchers** | .lnk, .url, .desktop | ~300 | Execution pointers with target/arguments |
| **Data/Config** | .html, .xml, .json, .ini, .vhd | ~1,000 | Passive data; potential steganography vectors |

### 12.2 File Category Taxonomy

```
9 Categories ──── 53 Extension Types ──── 55,271 Files
     │
     ├── NATIVE_BINARY  →  EXE, DLL, SYS, ELF, MACHO, SO, SCR, CPL
     ├── MANAGED_CODE   →  JAR, CLASS, APK, DEX
     ├── SCRIPT         →  JS, VBS, PS1, BAT, CMD, SH, PY, PL, LUA, PHP, HTA, WSF, AU3, JSE, VBE
     ├── OFFICE_OLE     →  DOC, DOCX, DOCM, XLS, XLSX, XLSM, XLL, PPT, PPTX, PPAM
     ├── RICH_DOC       →  PDF, RTF
     ├── ARCHIVE        →  ZIP, 7Z, RAR, GZ, TAR, ISO, IMG, CAB
     ├── INSTALLER      →  MSI, DMG
     ├── LAUNCHER       →  LNK, URL, DESKTOP
     └── DATA_CONFIG    →  HTML, XML, JSON, INI, VHD
```

---

## 13. Evaluation Metrics

**Module**: [model/evaluator.py](file:///Volumes/MALHARA/CPG/uir/model/evaluator.py)

The framework computes comprehensive binary classification metrics:

| Metric | Formula | Significance |
|:---|:---|:---|
| **Accuracy** | (TP + TN) / Total | Overall correctness |
| **Precision** | TP / (TP + FP) | Of predicted malware, how many are truly malicious |
| **Recall** | TP / (TP + FN) | Of actual malware, how many are detected |
| **F1 Score** | 2 × P × R / (P + R) | Harmonic mean of precision and recall |
| **FPR** | FP / (FP + TN) | False alarm rate |
| **FNR** | FN / (FN + TP) | Missed malware rate (critical for security) |
| **ROC-AUC** | Area under ROC curve | Discrimination ability across thresholds |

Additionally, [analyze_errors()](file:///Volumes/MALHARA/CPG/uir/model/evaluator.py#96-113) identifies specific false positive and false negative samples for post-hoc analysis.

---

## 14. Project Structure Reference

```
CPG/
├── uir/                              # Main package
│   ├── __init__.py                   # Package init, version
│   ├── config.py                     # Pydantic configuration (306 lines)
│   │
│   ├── extraction/                   # Phase 1: Recursive Extraction
│   │   ├── file_identifier.py        # Magic bytes + extension detection (401 lines)
│   │   ├── recursive_engine.py       # BFS recursive unpacker (247 lines)
│   │   ├── archive_extractor.py      # ZIP/RAR/7z/TAR/GZ/CAB (299 lines)
│   │   ├── disk_image_extractor.py   # ISO/IMG/VHD via pycdlib (217 lines)
│   │   └── msi_extractor.py          # MSI OLE + CustomAction (271 lines)
│   │
│   ├── lifting/                      # Phase 2: Domain-Specific Lifting
│   │   ├── base_lifter.py            # Abstract base + data classes (204 lines)
│   │   ├── binary_lifter.py          # PE/ELF/Mach-O analysis (547 lines)
│   │   ├── script_lifter.py          # JS/PY/PS1/VBS/BAT/SH (173 lines)
│   │   ├── document_lifter.py        # DOC/PDF/RTF + VBA extraction (265 lines)
│   │   └── launcher_lifter.py        # LNK/URL synthetic call graphs (252 lines)
│   │
│   ├── cpg/                          # Phase 3: Code Property Graph
│   │   ├── schema.py                 # Node/Edge types + operator mapping (248 lines)
│   │   ├── builder.py                # LiftedRep → CPG construction (243 lines)
│   │   └── graph.py                  # CPG data structure + I/O (334 lines)
│   │
│   ├── tokenization/                 # Phase 4: Feature Engineering
│   │   ├── vocabulary.py             # Semantic vocabulary (160 lines)
│   │   ├── bpe_tokenizer.py          # Byte-Pair Encoding (188 lines)
│   │   ├── value_abstractor.py       # Numeric/string abstraction (149 lines)
│   │   └── embedding.py              # PyTorch embedding layer (183 lines)
│   │
│   ├── model/                        # Phase 5: Deep Learning
│   │   ├── hgt.py                    # HGT model architecture (268 lines)
│   │   ├── dataset.py                # PyTorch CPG dataset (244 lines)
│   │   ├── trainer.py                # Training loop + contrastive loss (254 lines)
│   │   └── evaluator.py              # Metrics + confusion matrix (126 lines)
│   │
│   └── pipeline/                     # Orchestration
│       ├── processor.py              # Single-file end-to-end (165 lines)
│       ├── batch_processor.py        # Hardware-aware batch processing (423 lines)
│       ├── accelerator.py            # Hardware detection + numpy accel (378 lines)
│       └── cli.py                    # Command-line interface (321 lines)
│
├── setup.py                          # Package installation
├── requirements.txt                  # Dependencies
├── malware_dataset/                  # Raw input files (55,271 files)
├── cpgs/                             # Generated CPG JSON files
├── checkpoints/                      # Model checkpoints
└── cpg_cache/                        # CPG cache directory
```

**Total implementation**: ~5,700 lines of Python across 23 modules.

---

## 15. References

1. CodeGrafter: Unifying Source and Binary Graphs for Robust Vulnerability Detection — [ResearchGate](https://www.researchgate.net/publication/393572768)
2. Joern Documentation: Code Property Graph Overview — [docs.joern.io](https://docs.joern.io/)
3. Code Property Graph Specification 1.1 — [cpg.joern.io](https://cpg.joern.io/)
4. ExtractCode: Forensic archive extraction — [PyPI](https://pypi.org/project/extractcode/)
5. Unblob: Universal extraction suite — [unblob.org](https://unblob.org/)
6. Toward the Detection of Polyglot Files — [Oak Ridge National Laboratory](https://impact.ornl.gov/en/publications/toward-the-detection-of-polyglot-files/)
7. Emulating Ghidra's PCode: Why/How — [Medium](https://medium.com/@cetfor/emulating-ghidras-pcode-why-how-dd736d22dfb)
8. Joern Binary Support via Ghidra — [joern.io](https://joern.io/blog/binary-support-2021/)
9. AST-Based Deep Learning for Detecting Malicious PowerShell — [arXiv](https://arxiv.org/pdf/1810.09230)
10. A Survey of Heterogeneous Graph Neural Networks for Cybersecurity — [arXiv](https://arxiv.org/pdf/2510.26307)
11. GraphCodeBERT: Pre-Training Code Representations with Data Flow — [arXiv](https://huang.isis.vanderbilt.edu/cs8395/readings/graphcodebert.pdf)
12. Tokenization Is More Than Compression — [arXiv](https://arxiv.org/html/2402.18376v1)
13. The Method for Shellcode Extraction from Malicious Document Files — [ResearchGate](https://www.researchgate.net/publication/273576295)
14. Windows Shortcut (LNK) Malware Strategies — [Unit 42](https://unit42.paloaltonetworks.com/lnk-malware/)
15. Leveraging Code Property Graphs for Vulnerability Detection — [Fluid Attacks](https://fluidattacks.com/blog/code-property-graphs-for-analysis)

---

> **UIR v0.1.0** — ViGiL Project  
> *Unified Instruction Representation for Heterogeneous Malware Analysis*
