# ViGiL — Agent Reference

All 17 agents, their purpose, tools, inputs, and outputs.

---

## Agent 1: Sample Intake

**File:** `backend/agents/sample_intake.py`

**Purpose:** Validate PE format, compute cryptographic hashes, extract file metadata.

**Tools:** `pefile`, `hashlib` (stdlib)

**Output:**
```json
{
  "sha256": "...",
  "md5": "...",
  "sha1": "...",
  "arch": "x64",
  "compile_timestamp": "2023-01-15T10:30:00Z",
  "is_pe": true,
  "is_dll": false,
  "is_dotnet": false
}
```

**Fallback:** Basic MZ header check when pefile not installed.

---

## Agent 2: Static Analysis

**File:** `backend/agents/static_analysis.py`

**Purpose:** Deep static PE analysis — sections, imports, exports, strings.

**Tools:** `pefile`, `FLOSS` (subprocess), `strings` (subprocess), Python fallback

**Extracts:**
- PE sections with entropy
- Import/export tables
- Suspicious API calls
- URLs, IPs, domains, mutexes, registry keys, commands

**Output:** `StaticAnalysisResult` — 15+ fields

---

## Agent 3: Multi-Stage Unpacking

**File:** `backend/agents/unpacking.py`

**Purpose:** Detect packers and attempt multi-stage unpacking.

**Stage 1:** Signature detection (UPX, VMProtect, Themida, ASPack, etc.)  
**Stage 2:** PE heuristics — high entropy sections, RWX sections, tiny import tables  
**Stage 3:** Emulated unpacking via Speakeasy or UPX binary

**Detects:** UPX, MPRESS, ASPack, Themida, VMProtect, Enigma, PECompact, NsPack

**Output:**
```json
{
  "is_packed": true,
  "packer": "VMProtect",
  "layers": 3,
  "payload_recovered": false
}
```

---

## Agent 4: Capability Detection

**File:** `backend/agents/capability_detection.py`

**Tool:** CAPA binary (subprocess)  
**Fallback:** Import table heuristic analysis

**Detects:**
- Process Injection
- Credential Theft
- Keylogging
- Persistence
- Ransomware
- Network Beaconing
- System Discovery

---

## Agent 5: CFG Extraction

**File:** `backend/agents/cfg_extraction.py`

**Tools:** `angr` (primary), `rizin` (fallback)

**Generates:**
- Function list with complexity scores
- Suspicious function ranking
- API call graph
- `cfg.json`, `callgraph.json`

---

## Agent 6: Evasion Detection

**File:** `backend/agents/evasion_detection.py`

**Detects:**

| Category | Indicators |
|----------|-----------|
| Anti-VM | VirtualBox/VMware strings, registry, MAC prefix checks |
| Anti-Sandbox | Sleep loops, user activity checks, Sandboxie/Cuckoo markers |
| Anti-Debug | IsDebuggerPresent, NtQueryInformationProcess, PEB checks |
| Anti-Disassembly | Opaque predicates, overlapping instructions |
| API Obfuscation | GetProcAddress + LoadLibrary pattern, hashed API resolution |

**Output:** Evasion score 0–100

---

## Agent 7: Emulation Analysis

**File:** `backend/agents/emulation_analysis.py`

**Tool:** Microsoft Speakeasy  
**Fallback:** Static import → behavior inference

**Collects:**
- Files created/deleted
- Registry keys created/modified
- Network connections and domains
- Processes created
- DLLs loaded
- Persistence actions

---

## Agent 8: Similarity Analysis

**File:** `backend/agents/similarity_analysis.py`

**Approach:** Feature vector cosine similarity against pre-seeded family profiles

**Embedding features:** CAPA capabilities, imported APIs, ATT&CK techniques, string patterns

**Known families:** RedLine, Lumma, AgentTesla, AsyncRAT, Emotet, Cobalt Strike, Ransomware Generic

**Production upgrade:** Replace with FAISS index over real malware corpus

---

## Agent 9: Family Clustering

**File:** `backend/agents/family_clustering.py`

**Approach:** Threshold-based cluster assignment from similarity scores  
**Production upgrade:** HDBSCAN over behavioral embeddings

**Thresholds:**
- ≥ 0.85 → Assigned to known family
- 0.60–0.84 → "Similar to" family
- < 0.60 → Novel/Unknown cluster

---

## Agent 10: Threat Intelligence

**File:** `backend/agents/threat_intel.py`

**Sources:**
| Source | API Used |
|--------|---------|
| VirusTotal | `/api/v3/files/{hash}` |
| MalwareBazaar | `mb-api.abuse.ch` |
| AbuseIPDB | `/api/v2/check` |
| AlienVault OTX | `/api/v1/indicators/file/{hash}` |

**Demo Mode:** Realistic mock responses when API keys absent

---

## Agent 11: MITRE ATT&CK Mapping

**File:** `backend/agents/mitre_attack.py`

**Maps findings to 16+ techniques across:**
Discovery, Execution, Persistence, Defense Evasion, Credential Access, Command and Control, Impact

**Confidence** computed from trigger match count / total triggers per technique.

---

## Agent 12: RAG Intelligence

**File:** `backend/agents/rag_intelligence.py`

**Providers:** OpenAI GPT-4o | Google Gemini | Ollama (local)

**Knowledge Base:** MITRE ATT&CK descriptions, malware family reports, CAPA rules, research notes

**Retrieval:** Keyword-based KB search (upgrade to vector search with Qdrant)

**Generates:** Evidence-backed analyst explanation referencing specific KB sources

---

## Agent 13: LLM Decompilation

**File:** `backend/agents/decompilation.py`

**Decompiler:** Ghidra headless / RetDec (in production)  
**Demo:** Pre-defined suspicious function templates (injection, anti-debug, crypto, network)

**LLM** generates 2-3 sentence technical summaries per function.

---

## Agent 14: YARA Generation

**File:** `backend/agents/yara_generation.py`

**Generates 3 rule types:**

1. **Generic** — Multi-indicator suspicious binary rule
2. **Family** — Family-specific API pattern rule  
3. **Sample** — Exact sample match using unique strings

**Output:** `generated.yara` (combined file)

---

## Agent 15: ATT&CK Navigator Export

**File:** `backend/agents/attack_navigator.py`

**Output:** MITRE ATT&CK Navigator 4.9.1 compatible layer JSON  
**Colors:** Red (high confidence) → Green (low confidence)

**Import at:** https://mitre-attack.github.io/attack-navigator/

---

## Agent 16: STIX Export

**File:** `backend/agents/stix_export.py`

**Generates STIX 2.1 objects:**
- `identity` (ViGiL tool)
- `malware` (detected family)
- `indicator` (SHA256, IPs, domains)
- `attack-pattern` (MITRE techniques)
- `relationship` (indicator → malware)
- `report` (full bundle)

**Compatible with:** OpenCTI, MISP, TAXII 2.1 servers

---

## Phase 2: CrewAI Agentic AI (Hierarchical Engine)

The deterministic evidence from Phase 1 is passed into a Hierarchical CrewAI pipeline orchestrated by a Manager LLM. The manager delegates tasks to the following 5 specialized agents:

### 1. Static PE Analyst
**Role:** Deeply analyzes PE headers, entropy, sections, and structural anomalies.
**Input:** Static analysis, unpacking results.
**Output:** Assessment of structural malice (e.g., "Highly packed with RWX sections indicating a loader").

### 2. Behavioral Analyst
**Role:** Interprets emulation traces, evasion techniques, and capability flags (CAPA).
**Input:** Emulation, evasion, capabilities, CFG.
**Output:** Behavioral threat assessment (e.g., "Attempts process injection and anti-debug checks").

### 3. Threat Intel Analyst
**Role:** Correlates hashes, domains, and similarity clusters against known threat actors.
**Input:** Threat Intel, similarity analysis, family clustering.
**Output:** Attribution and external reputation context (e.g., "Matches AgentTesla cluster and flagged by VT").

### 4. Verdict Analyst
**Role:** Synthesizes the findings of the three specialized analysts to form a conclusive verdict.
**Input:** Thoughts from Static, Behavioral, and Threat Intel agents.
**Output:** Final Verdict (malicious/suspicious/clean), Confidence Score, Malware Family, and Key Evidence.

### 5. Report Writer
**Role:** Drafts an executive summary and defensive recommendations based on the final verdict.
**Input:** The final verdict and key evidence.
**Output:** Executive summary paragraph and bulleted recommended actions (e.g., "Isolate host, block C2 domains").

---

## Phase 3: Final Assembly

## Agent 17: Report Generation

**File:** `backend/agents/report_generation.py`

**Purpose:** Assemble all agent outputs and CrewAI verdict into the final `VigilReport`.

**Verdict computation** uses the CrewAI verdict. If CrewAI is disabled or fails, it falls back to weighted evidence scoring.

**Output:** `report.json` + in-memory `VigilReport` for WebSocket delivery

