"""
ViGiL — Analysis Pipeline Orchestrator
Runs all 17 agents sequentially, broadcasting WebSocket progress events.
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Awaitable

from loguru import logger

from models import (
    VigilReport, AgentProgressEvent,
    SampleIntakeResult, StaticAnalysisResult,
)
from agents.sample_intake import run_sample_intake
from agents.static_analysis import run_static_analysis
from agents.unpacking import run_unpacking_analysis
from agents.capability_detection import run_capability_detection
from agents.cfg_extraction import run_cfg_extraction
from agents.evasion_detection import run_evasion_detection
from agents.emulation_analysis import run_emulation_analysis
from agents.similarity_analysis import run_similarity_analysis
from agents.family_clustering import run_family_clustering
from agents.threat_intel import run_threat_intel
from agents.mitre_attack import run_mitre_attack_mapping
from agents.rag_intelligence import run_rag_intelligence
from agents.decompilation import run_decompilation
from agents.yara_generation import run_yara_generation
from agents.attack_navigator import run_attack_navigator_export
from agents.stix_export import run_stix_export
from agents.report_generation import generate_report


AGENTS = [
    "Sample Intake",
    "Static Analysis",
    "Unpacking",
    "Capability Detection",
    "CFG Extraction",
    "Threat Intelligence",
    "Evasion Detection",
    "Emulation Analysis",
    "Similarity Analysis",
    "Family Clustering",
    "MITRE ATT&CK Mapping",
    "RAG Intelligence",
    "LLM Decompilation",
    "YARA Generation",
    "ATT&CK Navigator Export",
    "STIX Export",
    "Report Generation",
]


ProgressCallback = Callable[[AgentProgressEvent], Awaitable[None]]


async def _emit(
    callback: ProgressCallback | None,
    job_id: str,
    agent_name: str,
    agent_index: int,
    status: str,
    message: str,
    result_summary: dict | None = None,
):
    if callback:
        event = AgentProgressEvent(
            job_id=job_id,
            agent_name=agent_name,
            agent_index=agent_index,
            total_agents=len(AGENTS),
            status=status,
            message=message,
            timestamp=datetime.now(timezone.utc).isoformat(),
            result_summary=result_summary,
        )
        await callback(event)


async def run_pipeline(
    job_id: str,
    file_path: Path,
    output_dir: Path,
    progress_callback: ProgressCallback | None = None,
) -> VigilReport:
    """
    Run the full ViGiL analysis pipeline.
    Broadcasts progress via progress_callback if provided.
    """
    start_time = time.time()
    filename = file_path.name
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"[Pipeline] Starting analysis for job {job_id}: {filename}")

    # ── Agent 1: Sample Intake ────────────────────────────────────────────────
    await _emit(progress_callback, job_id, "Sample Intake", 0, "started", f"Validating PE format and computing hashes for {filename}")
    sample_result = await asyncio.get_event_loop().run_in_executor(
        None, run_sample_intake, file_path
    )
    await _emit(progress_callback, job_id, "Sample Intake", 0, "completed",
        f"SHA256: {sample_result.sha256[:16]}... | Arch: {sample_result.arch} | PE: {sample_result.is_pe}",
        {"sha256": sample_result.sha256, "arch": sample_result.arch.value, "is_pe": sample_result.is_pe}
    )

    # ── Agent 2: Static Analysis ──────────────────────────────────────────────
    await _emit(progress_callback, job_id, "Static Analysis", 1, "started", "Extracting imports, strings, sections, entropy...")
    static_result = await asyncio.get_event_loop().run_in_executor(
        None, run_static_analysis, file_path
    )
    await _emit(progress_callback, job_id, "Static Analysis", 1, "completed",
        f"Sections: {len(static_result.sections)} | Imports: {len(static_result.imports)} | URLs: {len(static_result.urls)}",
        {"sections": len(static_result.sections), "imports": len(static_result.imports), "suspicious_strings": len(static_result.suspicious_strings)}
    )

    # ── Agent 3: Unpacking ────────────────────────────────────────────────────
    await _emit(progress_callback, job_id, "Unpacking", 2, "started", "Detecting packers and attempting multi-stage unpacking...")
    unpack_result = await asyncio.get_event_loop().run_in_executor(
        None, run_unpacking_analysis, file_path, output_dir
    )
    await _emit(progress_callback, job_id, "Unpacking", 2, "completed",
        f"Packed: {unpack_result.is_packed} | Packer: {unpack_result.packer or 'N/A'} | Layers: {unpack_result.layers}",
        {"is_packed": unpack_result.is_packed, "packer": unpack_result.packer, "layers": unpack_result.layers}
    )

    # ── Agent 4: Capability Detection ─────────────────────────────────────────
    await _emit(progress_callback, job_id, "Capability Detection", 3, "started", "Running CAPA capability detection...")
    cap_result = await asyncio.get_event_loop().run_in_executor(
        None, run_capability_detection, file_path, static_result.imports
    )
    await _emit(progress_callback, job_id, "Capability Detection", 3, "completed",
        f"Capabilities: {len(cap_result.capabilities)} detected",
        {"capabilities": cap_result.capabilities[:5]}
    )

    # ── Agent 5: CFG Extraction ───────────────────────────────────────────────
    await _emit(progress_callback, job_id, "CFG Extraction", 4, "started", "Generating control flow and call graphs...")
    cfg_result = await asyncio.get_event_loop().run_in_executor(
        None, run_cfg_extraction, file_path, output_dir
    )
    await _emit(progress_callback, job_id, "CFG Extraction", 4, "completed",
        f"Functions: {cfg_result.function_count} | Avg complexity: {cfg_result.avg_complexity}",
        {"function_count": cfg_result.function_count, "suspicious": len(cfg_result.suspicious_functions)}
    )

    # ── Agent 6 (run order 5): Threat Intelligence ────────────────────────────
    await _emit(progress_callback, job_id, "Threat Intelligence", 5, "started", "Querying threat intelligence APIs...")
    intel_result = await run_threat_intel(
        sha256=sample_result.sha256,
        ips=static_result.ips,
        domains=static_result.domains,
    )
    await _emit(progress_callback, job_id, "Threat Intelligence", 5, "completed",
        f"VT: {intel_result.virustotal_detections}/{intel_result.virustotal_total} | Family: {intel_result.known_family or 'Unknown'}",
        {"detections": intel_result.virustotal_detections, "family": intel_result.known_family, "demo_mode": intel_result.demo_mode}
    )

    # ── Agent 7 (run order 6): Evasion Detection ──────────────────────────────
    await _emit(progress_callback, job_id, "Evasion Detection", 6, "started", "Detecting anti-VM, anti-debug, API obfuscation...")
    evasion_result = await asyncio.get_event_loop().run_in_executor(
        None, run_evasion_detection, file_path,
        static_result.suspicious_strings + static_result.urls + static_result.domains,
        static_result.imports
    )
    await _emit(progress_callback, job_id, "Evasion Detection", 6, "completed",
        f"Evasion score: {evasion_result.evasion_score}/100 | Anti-VM: {evasion_result.anti_vm} | Anti-Debug: {evasion_result.anti_debug}",
        {"score": evasion_result.evasion_score, "anti_vm": evasion_result.anti_vm, "anti_debug": evasion_result.anti_debug}
    )

    # ── Agent 8 (run order 7): Emulation Analysis ─────────────────────────────
    await _emit(progress_callback, job_id, "Emulation Analysis", 7, "started", "Running behavioral emulation via Speakeasy...")
    emu_result = await asyncio.get_event_loop().run_in_executor(
        None, run_emulation_analysis, file_path, static_result.imports,
        static_result.suspicious_strings + static_result.urls + static_result.domains
    )
    await _emit(progress_callback, job_id, "Emulation Analysis", 7, "completed",
        f"Files: {len(emu_result.files_created)} | Registry: {len(emu_result.registry_keys_created)} | Domains: {len(emu_result.domains_contacted)}",
        {"files_created": len(emu_result.files_created), "domains": emu_result.domains_contacted[:3]}
    )

    # ── Agent 9 (run order 8): Similarity Analysis ────────────────────────────
    await _emit(progress_callback, job_id, "Similarity Analysis", 8, "started", "Computing family similarity embeddings...")
    all_import_funcs = [fn for imp in static_result.imports for fn in imp.functions]
    technique_ids = []  # Will be populated after MITRE mapping
    sim_result = await asyncio.get_event_loop().run_in_executor(
        None, run_similarity_analysis,
        cap_result.capabilities, all_import_funcs, technique_ids,
        static_result.suspicious_strings + static_result.domains
    )
    await _emit(progress_callback, job_id, "Similarity Analysis", 8, "completed",
        f"Top match: {sim_result.top_family} ({sim_result.top_similarity:.0%}) | Matches: {len(sim_result.matches)}",
        {"top_family": sim_result.top_family, "top_similarity": sim_result.top_similarity, "matches": len(sim_result.matches)}
    )

    # ── Agent 10 (run order 9): Family Clustering ─────────────────────────────
    await _emit(progress_callback, job_id, "Family Clustering", 9, "started", "Running HDBSCAN family clustering...")
    cluster_result = await asyncio.get_event_loop().run_in_executor(
        None, run_family_clustering,
        [m.model_dump() for m in sim_result.matches],
        cap_result.capabilities
    )
    await _emit(progress_callback, job_id, "Family Clustering", 9, "completed",
        f"Cluster: {cluster_result.cluster_label} | Novel: {cluster_result.is_novel} | Related: {cluster_result.related_samples}",
        {"cluster": cluster_result.cluster_label, "is_novel": cluster_result.is_novel}
    )

    # ── Agent 11 (run order 10): MITRE ATT&CK Mapping ────────────────────────
    await _emit(progress_callback, job_id, "MITRE ATT&CK Mapping", 10, "started", "Mapping findings to MITRE ATT&CK framework...")
    mitre_result = await asyncio.get_event_loop().run_in_executor(
        None, run_mitre_attack_mapping,
        cap_result.capabilities,
        evasion_result.model_dump(),
        emu_result.model_dump(),
        static_result.suspicious_strings + static_result.domains,
        all_import_funcs
    )
    await _emit(progress_callback, job_id, "MITRE ATT&CK Mapping", 10, "completed",
        f"Techniques: {mitre_result.technique_count} | Tactics: {', '.join(mitre_result.tactics_covered[:3])}",
        {"technique_count": mitre_result.technique_count, "tactics": mitre_result.tactics_covered}
    )

    # ── Agent 12 (run order 11): RAG Intelligence ─────────────────────────────
    await _emit(progress_callback, job_id, "RAG Intelligence", 11, "started", "Generating evidence-backed analyst explanation...")
    tech_ids = [t.technique_id for t in mitre_result.techniques]
    rag_result = await run_rag_intelligence(
        capabilities=cap_result.capabilities,
        evasion=evasion_result.model_dump(),
        techniques=tech_ids,
        family=sim_result.top_family or intel_result.known_family,
        threat_level="malicious" if intel_result.is_known_malware else "suspicious",
    )
    await _emit(progress_callback, job_id, "RAG Intelligence", 11, "completed",
        "Evidence-backed explanation generated",
        {"sources": rag_result.evidence_sources}
    )

    # ── Agent 13 (run order 12): Decompilation ────────────────────────────────
    await _emit(progress_callback, job_id, "LLM Decompilation", 12, "started", "Decompiling suspicious functions with LLM summaries...")
    decomp_result = await run_decompilation(
        file_path=file_path,
        suspicious_functions=cfg_result.suspicious_functions,
    )
    await _emit(progress_callback, job_id, "LLM Decompilation", 12, "completed",
        f"Functions analyzed: {len(decomp_result.functions_analyzed)} | Suspicious: {decomp_result.total_suspicious}",
        {"functions_analyzed": len(decomp_result.functions_analyzed)}
    )

    # ── Agent 14 (run order 13): YARA Generation ──────────────────────────────
    await _emit(progress_callback, job_id, "YARA Generation", 13, "started", "Generating YARA hunting rules...")
    yara_result = await asyncio.get_event_loop().run_in_executor(
        None, run_yara_generation,
        sample_result.sha256, sample_result.md5,
        static_result.suspicious_strings, all_import_funcs,
        cap_result.capabilities, tech_ids,
        sim_result.top_family or intel_result.known_family,
        output_dir
    )
    await _emit(progress_callback, job_id, "YARA Generation", 13, "completed",
        f"Generated {len(yara_result.rules)} YARA rules",
        {"rule_count": len(yara_result.rules), "types": [r.rule_type for r in yara_result.rules]}
    )

    # ── Agent 15 (run order 14): ATT&CK Navigator Export ─────────────────────
    await _emit(progress_callback, job_id, "ATT&CK Navigator Export", 14, "started", "Generating ATT&CK Navigator layer...")
    nav_result = await asyncio.get_event_loop().run_in_executor(
        None, run_attack_navigator_export,
        [t.model_dump() for t in mitre_result.techniques],
        filename,
        output_dir
    )
    await _emit(progress_callback, job_id, "ATT&CK Navigator Export", 14, "completed",
        f"Navigator layer with {len(mitre_result.techniques)} techniques saved",
        {"techniques": len(mitre_result.techniques)}
    )

    # ── Agent 16 (run order 15): STIX Export ──────────────────────────────────
    await _emit(progress_callback, job_id, "STIX Export", 15, "started", "Generating STIX 2.1 threat intelligence bundle...")
    stix_result = await asyncio.get_event_loop().run_in_executor(
        None, run_stix_export,
        sample_result.sha256, filename,
        sim_result.top_family or intel_result.known_family,
        cap_result.capabilities,
        [t.model_dump() for t in mitre_result.techniques],
        static_result.ips, static_result.domains, static_result.urls,
        "malicious" if intel_result.is_known_malware else "suspicious",
        output_dir
    )
    await _emit(progress_callback, job_id, "STIX Export", 15, "completed",
        f"STIX bundle with {stix_result.objects_generated} objects generated",
        {"objects": stix_result.objects_generated}
    )

    # ── Agent 17 (run order 16): Report Generation ────────────────────────────
    await _emit(progress_callback, job_id, "Report Generation", 16, "started", "Assembling final forensic report...")
    duration = time.time() - start_time

    # Collect artifact paths
    artifacts = {}
    if yara_result.combined_yara_path:
        artifacts["yara"] = yara_result.combined_yara_path
    if nav_result.navigator_json_path:
        artifacts["attack_navigator"] = nav_result.navigator_json_path
    if stix_result.stix_json_path:
        artifacts["stix"] = stix_result.stix_json_path

    final_report = await asyncio.get_event_loop().run_in_executor(
        None, generate_report,
        job_id, filename, duration,
        sample_result, static_result, unpack_result,
        cap_result, cfg_result, evasion_result, emu_result,
        sim_result, cluster_result, intel_result,
        mitre_result, rag_result, decomp_result,
        yara_result, nav_result, stix_result,
        artifacts, output_dir
    )

    await _emit(progress_callback, job_id, "Report Generation", 16, "completed",
        f"Analysis complete — Threat level: {final_report.threat_level.value.upper()} ({final_report.confidence_score:.0%} confidence)",
        {"threat_level": final_report.threat_level.value, "confidence": final_report.confidence_score}
    )

    logger.info(f"[Pipeline] Completed in {duration:.1f}s — Verdict: {final_report.threat_level.value}")
    return final_report
