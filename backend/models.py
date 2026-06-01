"""
ViGiL — Pydantic Data Models
All structured outputs from each agent and final report schema.
"""
from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ThreatLevel(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class Architecture(str, Enum):
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    UNKNOWN = "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Agent Output Models
# ─────────────────────────────────────────────────────────────────────────────

class SampleIntakeResult(BaseModel):
    sha256: str
    md5: str
    sha1: str
    file_size: int
    file_type: str
    arch: Architecture
    compile_timestamp: Optional[str] = None
    is_pe: bool
    is_dll: bool
    is_dotnet: bool
    subsystem: Optional[str] = None
    machine_type: Optional[str] = None


class PESection(BaseModel):
    name: str
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: str


class Import(BaseModel):
    dll: str
    functions: list[str]


class StaticAnalysisResult(BaseModel):
    sections: list[PESection] = Field(default_factory=list)
    imports: list[Import] = Field(default_factory=list)
    exports: list[str] = Field(default_factory=list)
    suspicious_strings: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    mutexes: list[str] = Field(default_factory=list)
    registry_keys: list[str] = Field(default_factory=list)
    commands: list[str] = Field(default_factory=list)
    has_overlay: bool = False
    has_tls_callbacks: bool = False
    has_certificate: bool = False
    average_entropy: float = 0.0
    high_entropy_sections: list[str] = Field(default_factory=list)


class UnpackingResult(BaseModel):
    is_packed: bool
    packer: Optional[str] = None
    layers: int = 0
    payload_recovered: bool = False
    layer_details: list[dict] = Field(default_factory=list)
    rwx_sections: bool = False
    suspicious_import_count: bool = False


class CapabilityResult(BaseModel):
    capabilities: list[str] = Field(default_factory=list)
    has_credential_theft: bool = False
    has_keylogging: bool = False
    has_persistence: bool = False
    has_ransomware: bool = False
    has_injection: bool = False
    has_network_beaconing: bool = False
    has_discovery: bool = False
    raw_capa_output: Optional[dict] = None


class CFGResult(BaseModel):
    function_count: int = 0
    avg_complexity: float = 0.0
    suspicious_functions: list[dict] = Field(default_factory=list)
    api_call_graph: dict = Field(default_factory=dict)
    cfg_svg_path: Optional[str] = None
    cfg_json_path: Optional[str] = None
    callgraph_json_path: Optional[str] = None


class EvasionResult(BaseModel):
    anti_vm: bool = False
    anti_vm_techniques: list[str] = Field(default_factory=list)
    anti_sandbox: bool = False
    anti_sandbox_techniques: list[str] = Field(default_factory=list)
    anti_debug: bool = False
    anti_debug_techniques: list[str] = Field(default_factory=list)
    anti_disassembly: bool = False
    anti_disassembly_techniques: list[str] = Field(default_factory=list)
    api_obfuscation: bool = False
    api_obfuscation_techniques: list[str] = Field(default_factory=list)
    evasion_score: int = 0  # 0–100


class EmulationResult(BaseModel):
    files_created: list[str] = Field(default_factory=list)
    files_deleted: list[str] = Field(default_factory=list)
    registry_keys_created: list[str] = Field(default_factory=list)
    registry_keys_modified: list[str] = Field(default_factory=list)
    network_connections: list[dict] = Field(default_factory=list)
    domains_contacted: list[str] = Field(default_factory=list)
    processes_created: list[str] = Field(default_factory=list)
    dlls_loaded: list[str] = Field(default_factory=list)
    persistence_actions: list[str] = Field(default_factory=list)
    api_calls: list[str] = Field(default_factory=list)


class SimilarityMatch(BaseModel):
    family: str
    similarity: float
    sample_hash: Optional[str] = None
    source: str = "faiss"


class SimilarityResult(BaseModel):
    matches: list[SimilarityMatch] = Field(default_factory=list)
    top_family: Optional[str] = None
    top_similarity: float = 0.0
    embedding_features: list[str] = Field(default_factory=list)


class ClusteringResult(BaseModel):
    cluster_id: Optional[str] = None
    cluster_label: str = "unknown"
    related_samples: int = 0
    is_novel: bool = True
    nearest_family: Optional[str] = None


class ThreatIntelResult(BaseModel):
    virustotal_detections: int = 0
    virustotal_total: int = 0
    virustotal_verdict: Optional[str] = None
    malwarebazaar_tags: list[str] = Field(default_factory=list)
    malwarebazaar_family: Optional[str] = None
    abuse_ip_reports: dict = Field(default_factory=dict)
    otx_pulses: list[str] = Field(default_factory=list)
    known_family: Optional[str] = None
    campaign: Optional[str] = None
    threat_actor: Optional[str] = None
    is_known_malware: bool = False
    demo_mode: bool = True


class MITRETechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    confidence: float = 1.0


class MITREResult(BaseModel):
    techniques: list[MITRETechnique] = Field(default_factory=list)
    tactics_covered: list[str] = Field(default_factory=list)
    technique_count: int = 0


class RAGExplanation(BaseModel):
    summary: str
    evidence_sources: list[str] = Field(default_factory=list)
    related_reports: list[str] = Field(default_factory=list)
    risk_explanation: str = ""
    analyst_notes: str = ""


class DecompiledFunction(BaseModel):
    function_name: str
    address: str
    decompiled_code: str
    llm_summary: str
    category: str  # injection | persistence | crypto | network | other
    suspicion_score: float = 0.0


class DecompilationResult(BaseModel):
    functions_analyzed: list[DecompiledFunction] = Field(default_factory=list)
    total_suspicious: int = 0


class YARARule(BaseModel):
    rule_name: str
    rule_type: str  # generic | family | sample
    description: str
    rule_content: str


class YARAResult(BaseModel):
    rules: list[YARARule] = Field(default_factory=list)
    combined_yara_path: Optional[str] = None


class ATTACKNavigatorResult(BaseModel):
    layer_json: dict = Field(default_factory=dict)
    navigator_json_path: Optional[str] = None


class STIXResult(BaseModel):
    stix_bundle: dict = Field(default_factory=dict)
    stix_json_path: Optional[str] = None
    objects_generated: int = 0


# ─────────────────────────────────────────────────────────────────────────────
# Final Report
# ─────────────────────────────────────────────────────────────────────────────

class VigilReport(BaseModel):
    # Metadata
    job_id: str
    filename: str
    analysis_timestamp: str
    analysis_duration_seconds: float = 0.0
    vigil_version: str = "1.0.0"

    # Verdict
    threat_level: ThreatLevel
    confidence_score: float  # 0.0 – 1.0
    verdict_reasoning: list[str] = Field(default_factory=list)

    # Agent Results
    sample_intake: Optional[SampleIntakeResult] = None
    static_analysis: Optional[StaticAnalysisResult] = None
    unpacking: Optional[UnpackingResult] = None
    capabilities: Optional[CapabilityResult] = None
    cfg: Optional[CFGResult] = None
    evasion: Optional[EvasionResult] = None
    emulation: Optional[EmulationResult] = None
    similarity: Optional[SimilarityResult] = None
    clustering: Optional[ClusteringResult] = None
    threat_intel: Optional[ThreatIntelResult] = None
    mitre: Optional[MITREResult] = None
    rag_explanation: Optional[RAGExplanation] = None
    decompilation: Optional[DecompilationResult] = None
    yara: Optional[YARAResult] = None
    attack_navigator: Optional[ATTACKNavigatorResult] = None
    stix: Optional[STIXResult] = None

    # Generated artifacts
    artifacts: dict[str, str] = Field(default_factory=dict)

    # CrewAI agentic verdict (populated after Phase 2 reasoning)
    agentic_verdict: Optional["AgenticVerdict"] = None


# ─────────────────────────────────────────────────────────────────────────────
# API Request / Response Models
# ─────────────────────────────────────────────────────────────────────────────

class AnalysisJob(BaseModel):
    job_id: str
    filename: str
    status: JobStatus
    created_at: str
    completed_at: Optional[str] = None
    current_agent: Optional[str] = None
    progress: int = 0  # 0–100
    error: Optional[str] = None


class AgentProgressEvent(BaseModel):
    job_id: str
    agent_name: str
    agent_index: int
    total_agents: int
    status: str  # started | completed | failed
    message: str
    timestamp: str
    result_summary: Optional[dict] = None


# ─────────────────────────────────────────────────────────────────────────────
# CrewAI Agentic Reasoning Models
# ─────────────────────────────────────────────────────────────────────────────

class AgentThought(BaseModel):
    """A single LLM agent's reasoning output."""
    agent_role: str
    findings: str          # free-text LLM reasoning
    key_indicators: list[str] = Field(default_factory=list)
    confidence: float = 0.5
    recommended_action: Optional[str] = None


class ReasoningChain(BaseModel):
    """Full chain of evidence from all CrewAI agents."""
    static_analysis_thought: Optional[AgentThought] = None
    behavioral_thought: Optional[AgentThought] = None
    threat_intel_thought: Optional[AgentThought] = None
    verdict_thought: Optional[AgentThought] = None
    report_thought: Optional[AgentThought] = None


class AgenticVerdict(BaseModel):
    """Final structured verdict produced by the CrewAI crew."""
    threat_level: ThreatLevel
    confidence_score: float = 0.5
    malware_family: Optional[str] = None
    malware_type: Optional[str] = None   # ransomware | trojan | rat | stealer | etc.
    threat_actor: Optional[str] = None
    executive_summary: str = ""
    key_evidence: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    reasoning_chain: ReasoningChain = Field(default_factory=ReasoningChain)
    llm_provider: str = "unknown"
    llm_model: str = "unknown"
    crew_process: str = "hierarchical"
