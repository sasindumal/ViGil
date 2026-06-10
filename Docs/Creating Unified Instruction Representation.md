# **Unified Instruction Representation for Heterogeneous Malware Analysis: A Deep Learning Framework**

## **1\. Introduction and Architectural Thesis**

The cybersecurity landscape has evolved from simple file-infecting viruses to complex, multi-stage kill chains that leverage a diverse ecosystem of file formats. The user's dataset, comprising 55,271 files across 53 distinct extensions, perfectly encapsulates this heterogeneity. It contains compiled binaries (.exe,.elf,.dll), intermediate bytecode (.class,.jar), interpreted scripts (.js,.ps1,.vbs), document-based vectors (.doc,.pdf,.xlsm), and system configuration artifacts (.lnk,.msi). Traditional deep learning approaches to malware detection have historically suffered from a "silo" problem: Convolutional Neural Networks (CNNs) are applied to raw binary images, Recurrent Neural Networks (RNNs) to text-based scripts, and Gradient Boosting machines to parsed PE headers. These disjointed models fail to capture the semantic equivalence of malicious logic across different representations. A "downloader" routine functions identically whether it is implemented in x86 assembly, PowerShell, or a VBA macro, yet a siloed approach treats these as fundamentally different phenomena.

To address this, the analysis necessitates the construction of a **Unified Instruction Representation (UIR)**. This representation must abstract away the syntactic idiosyncrasies of the underlying file formats to expose the core behavioral logic in a uniform, learnable manifold. This report proposes the adoption of the **Code Property Graph (CPG)** as the foundational data structure for this UIR. The CPG is a robust, graph-based representation that superimposes the Abstract Syntax Tree (AST), Control Flow Graph (CFG), and Program Dependence Graph (PDG) onto a single set of nodes. By lifting all 53 file types into this common graph schema, we can train a single, holistic **Heterogeneous Graph Transformer (HGT)** model capable of detecting malicious intent regardless of the delivery mechanism.

This report provides an exhaustive, expert-level specification for building this system. It details the **Recursive Lifting Pipeline** required to normalize the dataset, the **Domain-Specific Lifting Strategies** for translating each file cluster (Binaries, Scripts, Documents) into the CPG, and the **Deep Learning Architecture** required to embed these graphs for classification. The analysis leverages cutting-edge research in binary analysis, graph representation learning, and compiler theory to ensure the proposed solution is both theoretically sound and operationally viable.

## ---

**2\. Dataset Characterization and The Challenge of Heterogeneity**

The provided dataset is non-trivial not only in its volume but in its variance. The distribution of file types reveals a "long tail" composition, where a few dominant types (Executables) are accompanied by a large number of minority types (Scripts, Configs, Polyglots) that often serve as critical pivots in infection chains.

### **2.1 detailed Taxonomy of the Dataset**

To design an effective IR, we must first categorize the 53 file extensions based on their execution semantics rather than their file headers.

| Category | Extensions | Count | Semantic Characteristics |
| :---- | :---- | :---- | :---- |
| **Native Binaries** | .exe,.elf,.dll,.sys,.macho,.so,.scr,.cpl | \~49,000 | Direct CPU execution. Logic encoded in machine instructions (x86, ARM, MIPS). Requires disassembly and architecture lifting. |
| **Managed Code** | .jar,.class,.apk,.dex,.xapk | \~620 | VM-based execution (JVM, Dalvik). Logic encoded in bytecode. Requires decompilation or intermediate lifting. |
| **Scripts** | .js,.vbs,.ps1,.bat,.sh,.py,.pl,.lua,.php,.hta,.wsf,.cmd,.au3,.jse,.vbe | \~4,500 | Interpreted execution. Logic encoded in high-level text. Requires parsing (AST generation) and obfuscation handling. |
| **Office/OLE** | .doc,.docx,.xls,.xlsx,.xlsm,.ppam,.ppt,.pptx,.docm,.xll | \~2,500 | Compound storage formats. Logic embedded as VBA macros or OLE objects. Requires container parsing and stream extraction. |
| **Rich Docs** | .pdf,.rtf | \~185 | Presentation formats. Logic embedded as JS, Actions, or Shellcode. Requires object parsing and entropy analysis. |
| **Archives** | .zip,.7z,.rar,.gz,.tar,.iso,.img,.cab,.xz,.bz2,.tgz,.lz,.arj,.ace,.z,.lzh,.uue,.r00-r09 | \~3,000 | Containers. No inherent logic, but conceal payloads. Requires recursive extraction and polyglot detection. |
| **Installers** | .msi,.dmg | \~470 | Database-driven execution. Logic stored in tables (CustomAction). Requires database querying and script extraction. |
| **Launchers** | .lnk,.url,.desktop | \~300 | Execution pointers. Logic defined in arguments/targets. Requires synthetic call graph generation. |
| **Data/Config** | .html,.svg,.xml,.pem,.json,.ini,.geo,.vhd,.daa | \~1,000 | Passive data. Potential for steganography or polyglot payloads. Requires entropy and structure analysis. |

### **2.2 The Semantic Gap Problem**

The central challenge is the **Semantic Gap**. A Convolutional Neural Network (CNN) trained on the byte sequence of an .exe learns features related to the PE Header structure (e.g., MZ, PE\\0\\0) and x86 opcodes. If we feed a .js file to this same model, the byte patterns are fundamentally different (ASCII text, high entropy in variable names). The model cannot generalize.

Furthermore, traditional NLP models like BERT are excellent for source code (sequential token streams) but struggle with compiled binaries where the control flow is non-linear (jumps, loops, calls). Binaries are graphs, not sequences. Conversely, Graph Neural Networks (GNNs) are excellent for structure but require a graph input.

The **Code Property Graph (CPG)** bridges this gap.1 By converting *all* input types into a CPG, we normalize the data. A loop in assembly becomes a cyclic subgraph in the CPG. A loop in Python becomes a cyclic subgraph in the CPG. The deep learning model, trained on these graphs, learns the concept of "looping behavior" independent of the source language. This unification is the critical requirement for a robust IR.2

## ---

**3\. Phase 1: The Recursive Extraction and Normalization Layer**

Before any instruction representation can be generated, the raw files must be processed to expose their executable logic. The dataset contains over 3,000 archive and container files (.zip,.iso,.msi,.cab). In modern malware campaigns, threats are rarely distributed as naked executables; they are encapsulated in layers of obfuscation and compression to evade network perimeter scanners.

### **3.1 The Recursive Unpacking Engine**

We propose a **Recursive Decomposition Engine** utilizing the unblob and extractcode frameworks.4 Unlike standard consumer archivers (like WinZip), these tools are designed for forensic analysis. They do not rely solely on file extensions but use signature matching (magic bytes) to identify file types, and they are resilient to malformed headers often used by malware to crash standard tools.

#### **3.1.1 Handling Nested Archives and Polyglots**

The engine must operate recursively. A .zip file (1745 samples) may contain an .iso image (104 samples), which in turn contains a .lnk file (275 samples) and a hidden .dll (3515 samples).

* **Traversal Logic:** The engine identifies a container, extracts its contents to a temporary directory, and then re-queues the extracted files for identification. This process continues until a "Leaf Node" (executable, script, document, or config) is reached.  
* **Polyglot Handling:** A significant risk in this dataset is the presence of polyglot files (e.g., GIFAR \- a file that is valid as both a GIF image and a JAR archive).6 Malware uses these to bypass file type filters. The extraction engine must check *multiple* signatures. If a file is identified as a polyglot, it must be "forked" in the pipeline: one instance is processed as an image (entropy analysis), and the other as an archive (extraction). This ensures the deep learning model receives features from both interpretations.

#### **3.1.2 ISO, IMG, and VHD Parsing**

The dataset includes .iso (104), .img (109), .vhd (1), and .daa (1) files. These are disk images. Recent threat actors (e.g., Qakbot, Bumblebee) have heavily adopted these formats to bypass Windows "Mark-of-the-Web" (MotW) security controls.

* **Analysis Strategy:** Mounting these images via the OS is dangerous and inefficient for batch processing. Instead, we utilize Python libraries such as isoparser or pycdlib 8 to parse the ISO 9660 or UDF file system structures directly in memory. This allows for the extraction of the contained payloads (often .lnk files and hidden DLLs) without the overhead of mounting a virtual drive.

#### **3.1.3 MSI and Cab Extraction**

The 458 .msi and 31 .cab files represent installers. An .msi file is not a simple archive; it is a relational database containing installation instructions.

* **Extraction Logic:** We employ tools like lessmsi or the pymsi library.10 The extraction must be twofold:  
  1. **File Stream Extraction:** Extracting the binary payloads stored in the internal CAB streams.  
  2. **Table Dumping:** Exporting the CustomAction, Binary, and InstallExecuteSequence tables.12 These tables often contain embedded VBScript or JScript strings that execute immediately upon installation. These scripts must be extracted and forwarded to the script analysis pipeline.

### **3.2 File Type Identification and Dispatch**

Given the potential for extension spoofing (e.g., an .exe renamed to .txt), the pipeline must rely on content-based identification.

* **Tools:** We integrate libmagic (for MIME types) and TrID (for granular signature matching).  
* **Handling ".unknown" and Split Archives:** The 945 .unknown files and the split archives (.r00, .r01...) require distinct handling. Split archives must be reconstructed into their monolithic form before extraction. .unknown files are subjected to aggressive entropy analysis; high entropy segments are carved and tested against disassemblers to check for machine code signatures.13

## ---

**4\. Phase 2: Domain-Specific Lifting Strategies**

Once the containers are stripped away, we are left with the "payload" files. To generate a Unified Instruction Representation, we must "lift" these diverse formats into a common abstraction. We define **Ghidra P-Code** as the target Intermediate Representation (IR) for binaries, and a normalized **Abstract Syntax Tree (AST)** for scripts.

### **4.1 Lifting Native Binaries (.exe,.elf,.dll,.sys,.macho)**

This category represents the bulk of the dataset (\~49,000 files). The primary challenge is architecture diversity (x86, x64, ARM, MIPS, PowerPC) and format diversity (PE, ELF, Mach-O). Training a model on raw assembly is inefficient because ADD EAX, EBX (x86) and ADD R0, R1, R2 (ARM) look different but perform the same logic.

#### **4.1.1 The P-Code Advantage**

We select **Ghidra P-Code** as the unifying IR. P-Code is a Register Transfer Language (RTL) specifically designed for reverse engineering.14 It abstracts complex CISC instructions into a sequence of simple micro-operations.

* **Example:** The x86 instruction POP EAX implicitly reads from the stack, increments the stack pointer, and writes to a register. P-Code makes this explicit:  
  1. LOAD (const, 4\) \-\> EAX (Read value from stack RAM)  
  2. INT\_ADD ESP, 4 \-\> ESP (Increment Stack Pointer)  
* **Benefit:** By lifting all binaries to P-Code, the deep learning model trains on a uniform set of micro-operations (LOAD, STORE, INT\_ADD, BRANCH) regardless of the source architecture.15 This enables **Cross-Architecture Transfer Learning**: a buffer overflow pattern learned from x86 binaries can be detected in ARM IoT malware because the P-Code graph structure remains topologically identical.

#### **4.1.2 Implementation via Ghidra2CPG**

We utilize the **Ghidra2CPG** frontend from the Joern project.15 This tool:

1. Ingests the binary into Ghidra's headless analyzer.  
2. Performs disassembly and lifts instructions to P-Code.  
3. Constructs the Control Flow Graph (CFG) and Call Graph.  
4. Exports the result as a Code Property Graph (CPG).

### **4.2 Lifting Managed Code and Bytecode (.class,.jar,.apk)**

For Java (.class, .jar) and Android (.apk, .dex) files, the code is compiled to bytecode.

* **Decompilation:** We use tools like **Soot** or **JADX** to lift the bytecode to an intermediate representation (Jimple for Soot) or high-level Java source.  
* **CPG Generation:** The javasrc2cpg or jimple2cpg frontends map this representation into the CPG.17  
* **Normalization:** Android API calls (e.g., Context.getSystemService) are mapped to CALL nodes in the graph, structurally identical to Win32 API calls in the binary graphs.

### **4.3 Lifting Scripts (.js,.ps1,.vbs,.bat,.sh,.py)**

Scripts (\~4,500 files) present a different challenge: they are text-based and often heavily obfuscated.

* **Parsing to AST:** We utilize robust parsers like **Tree-sitter** or language-specific tools (e.g., Roslyn for PowerShell) to generate an Abstract Syntax Tree (AST).18  
* **Handling Obfuscation:** Script malware often uses eval() or base64 encoding to hide logic. A raw text model (RNN) might be fooled by variable randomization (var a \= 1 vs var xsd \= 1). The CPG solves this by focusing on **Data Flow**. Even if variable names change, the *structure* of how data moves from assignment to usage remains constant.20  
* **Dynamic Resolution:** For extreme obfuscation, we can employ a "Hybrid Lifting" approach. We run the script in a lightweight emulator (like box-js for JavaScript) to resolve the de-obfuscated code, and then generate the CPG from the *emulated* trace rather than the static source.21

### **4.4 Lifting Documents (.doc,.pdf,.rtf)**

Documents are not code; they are containers that *embed* code.

* **Macro Extraction:** For Office documents, we use oletools (olevba) to extract VBA macros. These are then treated as VBScript files and processed via the script pipeline.22  
* **Shellcode Hunting:** PDF and RTF files often exploit vulnerabilities using binary shellcode (e.g., heap sprays). We perform **Entropy Analysis** on the document streams. High-entropy blobs are carved out and run through a shellcode emulator (like libemu or speakeasy). If valid execution is detected, the shellcode is lifted to P-Code and attached to the document's graph representation as a "Payload" subgraph.24

### **4.5 Lifting Launchers and Configs (.lnk,.url,.xml)**

Files like .lnk (Shortcuts) define an execution intent.

* **Synthetic Call Graph:** We parse the LNK file to extract the Target and Arguments. We then construct a **Synthetic CPG**.27  
  * *Example:* A shortcut to cmd.exe /c powershell.exe \-enc \<payload\> is modeled as:  
    * CALL Node (cmd.exe) \-\> ARGUMENT Node (/c) \-\> CALL Node (powershell.exe).  
  * This normalizes the LNK file into the same graph structure as a shell script or a binary performing a CreateProcess call. The deep learning model can thus detect "Living off the Land" (LotL) attacks regardless of whether they originate from a .bat file or a .lnk file.

## ---

**5\. Theoretical Framework: The Unified Code Property Graph (U-CPG)**

The heart of the proposed system is the **Code Property Graph (CPG)**. This graph serves as the "universal translator," providing a single schema to represent the logic of all 53 file types.

### **5.1 The CPG Schema Definition**

The U-CPG is a directed, attributed multigraph $G \= (V, E, \\mu, \\nu)$ where $V$ is the set of nodes, $E$ is the set of edges, and $\\mu, \\nu$ are mapping functions for attributes.2

#### **5.1.1 Node Types (The "Nouns" of the IR)**

We define a minimized set of node types to ensure semantic alignment across languages:

* **METHOD:** Represents a function, subroutine, or global script scope.  
  * *Attributes:* name, signature, is\_external (true for API calls).  
* **BLOCK:** Represents a basic block (a sequence of instructions with one entry and one exit).  
  * *Attributes:* order, depth.  
* **CALL:** Represents an instruction that invokes another method or operator.  
  * *Attributes:* name (e.g., "memcpy", "ADD", "eval"), dispatch\_type (static/dynamic).  
* **CONTROL\_STRUCTURE:** Represents logic flow logic.  
  * *Attributes:* code ("IF", "WHILE", "TRY"), parser\_type\_name.  
* **IDENTIFIER / LITERAL:** Represents operands and data.  
  * *Attributes:* name (variable name), type (int, string), value (for literals).

#### **5.1.2 Edge Types (The "Verbs" of the IR)**

The CPG superimposes three distinct graphs onto these nodes 30:

1. **AST Edges (IS\_AST\_PARENT):** Represents syntactic containment.  
   * *Usage:* METHOD \-\> contains \-\> BLOCK \-\> contains \-\> CALL. This captures the hierarchical structure of the code.  
2. **CFG Edges (FLOWS\_TO):** Represents execution order.  
   * *Usage:* CALL(Instruction A) \-\> flows to \-\> CALL(Instruction B). This captures the temporal sequence of operations.  
3. **PDG Edges (REACHES, CONTROLS):** Represents data and control dependencies.  
   * *Usage:* IDENTIFIER(x defined at line 1\) \-\> reaches \-\> CALL(x used at line 5). This is the most critical edge type for malware analysis. It allows the model to "see through" obfuscation. If malware defines a malicious URL in a variable, renames the variable ten times, and then uses it in a Download function, the PDG edge connects the URL literal directly to the Download call, bypassing the obfuscation noise.

### **5.2 Mapping Heterogeneous Inputs to the Schema**

To ensure the deep learning model learns effectively, we must strictly define how different file types map to this schema.

| Feature | Binary (P-Code) | Script (AST) | LNK/Launcher |
| :---- | :---- | :---- | :---- |
| **Instruction** | Each P-Code operation (INT\_ADD, STORE) becomes a CALL node to an \<operator\>. | Each statement (x \= y \+ 1\) becomes a CALL node to \<operator\>.assignment. | The Target (cmd.exe) becomes a CALL node. |
| **Variables** | Registers (EAX, R1) and stack slots are mapped to IDENTIFIER nodes. | Variable names ($var) are mapped to IDENTIFIER nodes. | Arguments are mapped to LITERAL nodes. |
| **Control Flow** | Jumps/Branches form FLOWS\_TO edges. | If/While blocks form FLOWS\_TO edges. | Sequential execution forms FLOWS\_TO edges. |
| **API Calls** | Calls to imports (kernel32.dll) are CALL nodes with is\_external=true. | Calls to built-ins (WScript.Shell) are CALL nodes with is\_external=true. | The target binary is the external method. |

**Key Insight:** By normalizing operations to \<operator\> calls (e.g., mapping x86 ADD and JS \+ to the same \<operator\>.addition node), we enable the neural network to learn the *concept* of addition rather than the specific syntax.

## ---

**6\. Phase 3: Feature Engineering and Tokenization**

With the U-CPG constructed, we have a graph. To feed this into a deep learning model, we must vectorize the node attributes. The primary challenge is the **Out-Of-Vocabulary (OOV)** problem. Malware binaries contain millions of unique literals (memory addresses, randomized strings, large constants). A standard "bag-of-words" vocabulary would be infinitely large and sparse.

### **6.1 Semantic Tokenization Strategy**

We propose a **Hybrid Tokenization** strategy that balances vocabulary size with semantic fidelity.32

#### **6.1.1 The Semantic Vocabulary (Fixed)**

We define a small, fixed vocabulary for the structural elements of the CPG. This ensures the model focuses on the graph's *skeleton*.

* **Operators:** ADD, SUB, MUL, XOR, ASSIGN, EQ, GT, LT...  
* **Keywords:** IF, ELSE, WHILE, RETURN, TRY, CATCH...  
* **Node Types:** METHOD, BLOCK, CALL, IDENTIFIER, LITERAL...  
* **Registers:** REG\_GEN (generic register), REG\_SP (stack pointer), REG\_PC (program counter).

#### **6.1.2 Byte-Pair Encoding (BPE) for Identifiers**

For user-defined strings (variable names, function names, string literals), we use **Byte-Pair Encoding (BPE)**.34 BPE iteratively merges frequent character pairs.

* *Example:* A function named DownloadAndExecute might be tokenized as \`\`.  
* *Benefit:* This allows the model to handle unseen variable names by breaking them down into known sub-components. If malware uses DownloadPayload1 and DownloadPayload2, the model learns the common semantic root Download and Payload.

#### **6.1.3 Abstract Tokenization for Values**

Large integers and memory addresses are not treated as unique tokens. Instead, we apply **Value Abstraction** 35:

* **Small Integers:** Values between \-1000 and 1000 are kept as distinct tokens.  
* **Large Integers:** Values outside this range are mapped to a generic \<LARGE\_INT\> token.  
* **Memory Addresses:** Replaced with \<MEM\_ADDR\>.  
* **Magic Numbers:** Known constants (e.g., 0x4D5A for MZ header, 0x90 for NOP) are preserved in a specific "Allow List" vocabulary because they carry significant semantic weight in malware analysis.

### **6.2 Joint Embedding Space**

We train a **Joint Embedding Matrix**. Tokens from assembly (P-Code) and tokens from scripts (JS/PS1) share the same vector space. We initialize the embeddings such that semantically similar tokens (e.g., INT\_ADD from P-Code and \+ from JS) are close together. This initialization can be done using a pre-trained model like **CodeBERT** or **Word2Vec** trained on a mixed corpus of code.36

## ---

**7\. Deep Learning Architecture: Heterogeneous Graph Transformer (HGT)**

To learn from the U-CPG, we require a model architecture that respects the graph structure and the heterogeneity of the nodes. We strongly recommend the **Heterogeneous Graph Transformer (HGT)** 38 over standard Graph Convolutional Networks (GCNs).

### **7.1 Why HGT?**

Standard GCNs assume all nodes and edges are identical in type. In our U-CPG, a METHOD node is fundamentally different from a LITERAL node. A FLOWS\_TO edge (time) implies a different relationship than a REACHES edge (data).

* **Meta-Relations:** HGT introduces the concept of meta-relations (triplets of Source Type \- Edge Type \- Target Type). The model learns separate attention matrices for each meta-relation.  
* **Mechanism:** When updating the embedding of a CALL node, the HGT might assign high attention weight to incoming REACHES edges (data dependencies) and lower weight to IS\_AST\_PARENT edges.  
* **Result:** This allows the model to learn complex heuristics automatically. For example, it might learn that "A CALL node connected via REACHES to a LITERAL node containing a URL" is a strong indicator of a Downloader, while the same CALL node connected via FLOWS\_TO to a RETURN node is benign control flow.

### **7.2 Alternative: Graph-Augmented Sequence Models (GraphCodeBERT)**

Given the sequential nature of instructions, an alternative or complementary approach is to use **GraphCodeBERT**.39

* **Input:** We linearize the basic blocks of the graph into a sequence of tokens.  
* **Attention Mask:** Instead of allowing the Transformer to attend to *all* tokens (full $N^2$ complexity), we provide an attention mask derived from the CPG. A token is allowed to attend to another token only if they are connected in the graph (e.g., by a data flow edge).  
* **Advantage:** This effectively solves the "Long-Range Dependency" problem. In a binary, the definition of a variable and its usage might be thousands of instructions apart. A standard RNN would forget the context. GraphCodeBERT, guided by the data flow edge, sees them as "neighbors" in the attention mechanism, allowing it to detect logical connections across the entire binary.

### **7.3 Training Strategy: Contrastive Learning**

To maximize detection accuracy, particularly for the "Long Tail" classes (like the 1 .go file or 2 .class files), we recommend a **Contrastive Learning** objective.

* **Method:** We assume that malware from the same family (e.g., Emotet) shares subgraph structures, even if compiled differently or obfuscated.  
* **Loss Function:** We train the model to minimize the distance between embeddings of different files in the same family (Positive Pairs) and maximize the distance between malware and benign software (Negative Pairs). This forces the model to learn robust, invariant features of malicious behavior rather than overfitting to specific file artifacts.

## ---

**8\. Operationalizing the Pipeline**

Building this system for 55,271 files requires a robust engineering pipeline.

### **8.1 Infrastructure Specification**

* **Orchestration:** Use **Apache Airflow** to manage the dependency graph of tasks (Extraction \-\> Identification \-\> Lifting \-\> Embedding).  
* **Distributed Workers:**  
  * **Worker Type A (Heavy):** 16GB+ RAM instances running **Joern/Ghidra** for binary lifting.  
  * **Worker Type B (Light):** Node.js/Python instances for script parsing and archive extraction.  
* **Graph Database:** Use **OverflowDB** (the storage backend for Joern) or **Neo4j**. The graphs for 55k files will be significant; storage must be optimized for traversal speed.30

### **8.2 Optimization for Scale**

Processing 27,000 binaries through Ghidra is computationally expensive.

* **Function Hashing:** Implement **SimHash** or **Locality Sensitive Hashing (LSH)** on the P-Code of functions. Before adding a function to the CPG, check if it matches a known library function (e.g., openssl\_encrypt). If it matches, do not lift the entire subgraph; instead, replace it with a single LIBRARY\_CALL summary node. This reduces the graph size by 60-80% for statically linked binaries, focusing the learning on the unique (malicious) code.

## ---

**9\. Conclusion**

The requirement to create a unified Instruction Representation for a dataset spanning 53 distinct file types—from compiled machine code to interpreted scripts and serialized configurations—cannot be met by simple feature concatenation. It requires a fundamental shift to a **semantic-first** architecture.

By adopting the **Code Property Graph (CPG)** as the universal schema, utilizing **Recursive Lifting** to handle the nesting of modern malware, and employing **Heterogeneous Graph Transformers** for embedding, we create a system that is resilient to the "Tower of Babel" problem in cybersecurity. This framework normalizes the heterogeneous inputs into a single, mathematically rigorous manifold, allowing the deep learning model to learn the *behavior* of malware—the "intent"—rather than the syntax of its delivery. This approach not only satisfies the immediate requirement for the 55,271 files but provides a future-proof foundation for detecting novel, cross-modal threats.

## ---

**10\. References**

* **Code Property Graph & Joern:** 1  
* **Binary Lifting & P-Code:** 14  
* **Recursive Extraction & Unblob:** 4  
* **Graph Neural Networks (HGT/GCN):** 38  
* **GraphCodeBERT & Tokenization:** 32  
* **LNK & Document Analysis:** 24  
* **Polyglot Detection:** 6

#### **Works cited**

1. CodeGrafter: Unifying Source and Binary Graphs for Robust Vulnerability Detection | Request PDF \- ResearchGate, accessed January 16, 2026, [https://www.researchgate.net/publication/393572768\_CodeGrafter\_Unifying\_Source\_and\_Binary\_Graphs\_for\_Robust\_Vulnerability\_Detection](https://www.researchgate.net/publication/393572768_CodeGrafter_Unifying_Source_and_Binary_Graphs_for_Robust_Vulnerability_Detection)  
2. Joern Documentation: Overview, accessed January 16, 2026, [https://docs.joern.io/](https://docs.joern.io/)  
3. Code Property Graph | Joern Documentation, accessed January 16, 2026, [https://docs.joern.io/code-property-graph/](https://docs.joern.io/code-property-graph/)  
4. extractcode \- PyPI, accessed January 16, 2026, [https://pypi.org/project/extractcode/](https://pypi.org/project/extractcode/)  
5. Show HN: Unblob – extraction suite for 30+ file formats \- Hacker News, accessed January 16, 2026, [https://news.ycombinator.com/item?id=34434249](https://news.ycombinator.com/item?id=34434249)  
6. Toward the Detection of Polyglot Files \- Oak Ridge National Laboratory, accessed January 16, 2026, [https://impact.ornl.gov/en/publications/toward-the-detection-of-polyglot-files/](https://impact.ornl.gov/en/publications/toward-the-detection-of-polyglot-files/)  
7. Toward the Detection of Polyglot Files \- OSTI.GOV, accessed January 16, 2026, [https://www.osti.gov/servlets/purl/3002965](https://www.osti.gov/servlets/purl/3002965)  
8. barneygale/isoparser: Parser for the ISO 9660 disk image format \- GitHub, accessed January 16, 2026, [https://github.com/barneygale/isoparser](https://github.com/barneygale/isoparser)  
9. clalancette/pycdlib: Python library to read and write ISOs \- GitHub, accessed January 16, 2026, [https://github.com/clalancette/pycdlib](https://github.com/clalancette/pycdlib)  
10. lessmsi: A tool to view and extract the contents of an msi file, accessed January 16, 2026, [https://lessmsi.activescott.com/](https://lessmsi.activescott.com/)  
11. pymsi: cross-platform library \+ CLI util to read and extract Windows MSI file contents \- Reddit, accessed January 16, 2026, [https://www.reddit.com/r/opensource/comments/1lfh2qe/pymsi\_crossplatform\_library\_cli\_util\_to\_read\_and/](https://www.reddit.com/r/opensource/comments/1lfh2qe/pymsi_crossplatform_library_cli_util_to_read_and/)  
12. How to Export SQL Server Data to a Text File Format? \- GeeksforGeeks, accessed January 16, 2026, [https://www.geeksforgeeks.org/sql/how-to-export-sql-server-data-to-a-text-file-format/](https://www.geeksforgeeks.org/sql/how-to-export-sql-server-data-to-a-text-file-format/)  
13. unblob \- extract everything\!, accessed January 16, 2026, [https://unblob.org/](https://unblob.org/)  
14. Emulating Ghidra's PCode: Why/How | by John Toterhi | Medium, accessed January 16, 2026, [https://medium.com/@cetfor/emulating-ghidras-pcode-why-how-dd736d22dfb](https://medium.com/@cetfor/emulating-ghidras-pcode-why-how-dd736d22dfb)  
15. The Bug Hunter's Workbench | Joern Supports Binary, accessed January 16, 2026, [https://joern.io/blog/binary-support-2021/](https://joern.io/blog/binary-support-2021/)  
16. joern \- Scaladex, accessed January 16, 2026, [https://index.scala-lang.org/joernio/joern/artifacts/ghidra2cpg/2.0.328?](https://index.scala-lang.org/joernio/joern/artifacts/ghidra2cpg/2.0.328)  
17. Joern for Beginners: A How-To Guide for Source Code Analysis | by TutorialBoy | Medium, accessed January 16, 2026, [https://tutorialboy.medium.com/joern-for-beginners-a-how-to-guide-for-source-code-analysis-7d03e1d82f82](https://tutorialboy.medium.com/joern-for-beginners-a-how-to-guide-for-source-code-analysis-7d03e1d82f82)  
18. How we train AI to uncover malicious JavaScript intent and make web surfing safer, accessed January 16, 2026, [https://blog.cloudflare.com/how-we-train-ai-to-uncover-malicious-javascript-intent-and-make-web-surfing-safer/](https://blog.cloudflare.com/how-we-train-ai-to-uncover-malicious-javascript-intent-and-make-web-surfing-safer/)  
19. POSTER: AST-Based Deep Learning for Detecting Malicious PowerShell \- arXiv, accessed January 16, 2026, [https://arxiv.org/pdf/1810.09230](https://arxiv.org/pdf/1810.09230)  
20. Now You See Me, Now You Don't: Using LLMs to Obfuscate Malicious JavaScript, accessed January 16, 2026, [https://unit42.paloaltonetworks.com/using-llms-obfuscate-malicious-javascript/](https://unit42.paloaltonetworks.com/using-llms-obfuscate-malicious-javascript/)  
21. A NOVEL MODEL BASED ON DEEP TRANSFER LEARNING FOR DETECTING MALICIOUS JAVASCRIPT CODE, accessed January 16, 2026, [https://www.jatit.org/volumes/Vol102No18/21Vol102No18.pdf](https://www.jatit.org/volumes/Vol102No18/21Vol102No18.pdf)  
22. How to extract data from excel using VBA? \- Microsoft Q\&A, accessed January 16, 2026, [https://learn.microsoft.com/en-us/answers/questions/2338259/how-to-extract-data-from-excel-using-vba](https://learn.microsoft.com/en-us/answers/questions/2338259/how-to-extract-data-from-excel-using-vba)  
23. AI-DRIVEN DETECTION OF MALICIOUS MACROS IN OFFICE DOCUMENTS \- ijprems, accessed January 16, 2026, [https://www.ijprems.com/ijprems-paper/ai-driven-detection-of-malicious-macros-in-office-documents](https://www.ijprems.com/ijprems-paper/ai-driven-detection-of-malicious-macros-in-office-documents)  
24. (PDF) The Method for Shellcode Extraction from Malicious Document File Using Entropy and Emulation \- ResearchGate, accessed January 16, 2026, [https://www.researchgate.net/publication/273576295\_The\_Method\_for\_Shellcode\_Extraction\_from\_Malicious\_Document\_File\_Using\_Entropy\_and\_Emulation](https://www.researchgate.net/publication/273576295_The_Method_for_Shellcode_Extraction_from_Malicious_Document_File_Using_Entropy_and_Emulation)  
25. A Method for Shellcode Extractionfrom Malicious Document Files Using Entropy and Emulation, accessed January 16, 2026, [https://www.ijetch.org/vol8/866-ST005.pdf](https://www.ijetch.org/vol8/866-ST005.pdf)  
26. Malcat tip: fast unpacking of RTF payloads, accessed January 16, 2026, [https://malcat.fr/blog/malcat-tip-fast-unpacking-of-rtf-payloads/](https://malcat.fr/blog/malcat-tip-fast-unpacking-of-rtf-payloads/)  
27. Shortcut to Chaos: How LNK Files Are Exploited by Malware \- CybaVerse, accessed January 16, 2026, [https://www.cybaverse.co.uk/resources/shortcut-to-chaos-how-lnk-files-are-exploited-by-malware](https://www.cybaverse.co.uk/resources/shortcut-to-chaos-how-lnk-files-are-exploited-by-malware)  
28. Threat Analysis: Purple Team Series \- Taking Shortcuts… Using LNK Files for Initial Infection and Persistence \[NEST\] \- Cybereason, accessed January 16, 2026, [https://www.cybereason.com/hubfs/Insights/Research/threat-analysis-purple-team-taking-shortcuts-LNK-files.pdf](https://www.cybereason.com/hubfs/Insights/Research/threat-analysis-purple-team-taking-shortcuts-LNK-files.pdf)  
29. Code Property Graph Specification 1.1 \- Joern, accessed January 16, 2026, [https://cpg.joern.io/](https://cpg.joern.io/)  
30. Code Property Graph | Qwiet Docs, accessed January 16, 2026, [https://docs.shiftleft.io/core-concepts/code-property-graph](https://docs.shiftleft.io/core-concepts/code-property-graph)  
31. Leveraging code property graphs for vulnerability detection \- Fluid Attacks, accessed January 16, 2026, [https://fluidattacks.com/blog/code-property-graphs-for-analysis](https://fluidattacks.com/blog/code-property-graphs-for-analysis)  
32. Tokenization Is More Than Compression \- arXiv, accessed January 16, 2026, [https://arxiv.org/html/2402.18376v1](https://arxiv.org/html/2402.18376v1)  
33. How Different Tokenization Algorithms Impact LLMs and Transformer Models for Binary Code Analysis \- arXiv, accessed January 16, 2026, [https://arxiv.org/html/2511.03825v1](https://arxiv.org/html/2511.03825v1)  
34. BPE-Dropout vs. WordPiece: Subword Regularization Compared \- Newline.co, accessed January 16, 2026, [https://www.newline.co/@zaoyang/bpe-dropout-vs-wordpiece-subword-regularization-compared--68f1639d](https://www.newline.co/@zaoyang/bpe-dropout-vs-wordpiece-subword-regularization-compared--68f1639d)  
35. The first step is the hardest: pitfalls of representing and tokenizing temporal data for large language models \- NIH, accessed January 16, 2026, [https://pmc.ncbi.nlm.nih.gov/articles/PMC11339515/](https://pmc.ncbi.nlm.nih.gov/articles/PMC11339515/)  
36. AI-Assisted Programming Tasks Using Code Embeddings and Transformers \- MDPI, accessed January 16, 2026, [https://www.mdpi.com/2079-9292/13/4/767](https://www.mdpi.com/2079-9292/13/4/767)  
37. Malware Classification Using Dynamically Extracted API Call Embeddings \- MDPI, accessed January 16, 2026, [https://www.mdpi.com/2076-3417/14/13/5731](https://www.mdpi.com/2076-3417/14/13/5731)  
38. A Survey of Heterogeneous Graph Neural Networks for Cybersecurity Anomaly Detection \- arXiv, accessed January 16, 2026, [https://arxiv.org/pdf/2510.26307](https://arxiv.org/pdf/2510.26307)  
39. Improving Text-to-Code Generation with Features of Code Graph on GPT-2 \- MDPI, accessed January 16, 2026, [https://www.mdpi.com/2079-9292/10/21/2706](https://www.mdpi.com/2079-9292/10/21/2706)  
40. arXiv:2009.08366v4 \[cs.SE\] 13 Sep 2021, accessed January 16, 2026, [https://huang.isis.vanderbilt.edu/cs8395/readings/graphcodebert.pdf](https://huang.isis.vanderbilt.edu/cs8395/readings/graphcodebert.pdf)  
41. Testing Intermediate Representations for Binary Analysis, accessed January 16, 2026, [https://softsec.kaist.ac.kr/\~soomink/paper/ase17main-mainp491-p.pdf](https://softsec.kaist.ac.kr/~soomink/paper/ase17main-mainp491-p.pdf)  
42. What are graph embeddings ? \- NebulaGraph, accessed January 16, 2026, [https://www.nebula-graph.io/posts/graph-embeddings](https://www.nebula-graph.io/posts/graph-embeddings)  
43. Graph Neural Network and Some of GNN Applications: Everything You Need to Know, accessed January 16, 2026, [https://neptune.ai/blog/graph-neural-network-and-some-of-gnn-applications](https://neptune.ai/blog/graph-neural-network-and-some-of-gnn-applications)  
44. Graph Neural Networks Series | Part 3 | Node embedding | by Omar Hussein \- Medium, accessed January 16, 2026, [https://medium.com/the-modern-scientist/graph-neural-networks-series-part-3-node-embedding-36613cc967d5](https://medium.com/the-modern-scientist/graph-neural-networks-series-part-3-node-embedding-36613cc967d5)  
45. Augmenting the Interpretability of GraphCodeBERT for Code Similarity Tasks \- arXiv, accessed January 16, 2026, [https://arxiv.org/html/2410.05275v1](https://arxiv.org/html/2410.05275v1)  
46. Windows Shortcut (LNK) Malware Strategies, accessed January 16, 2026, [https://unit42.paloaltonetworks.com/lnk-malware/](https://unit42.paloaltonetworks.com/lnk-malware/)