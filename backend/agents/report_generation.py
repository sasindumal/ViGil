"""
ViGiL — Agent 17: Report Generation Agent
Produces the final VigilReport combining all agent outputs.
Computes threat verdict and confidence score based on evidence.
"""
from __future__ import annotations

import json
from pathlib import Path
from loguru import logger

from models import (
    VigilReport, ThreatLevel,
    SampleIntakeResult, StaticAnalysisResult, UnpackingResult,
    CapabilityResult, CFGResult, EvasionResult, EmulationResult,
    SimilarityResult, ClusteringResult, ThreatIntelResult,
    MITREResult, RAGExplanation, DecompilationResult,
    YARAResult, ATTACKNavigatorResult, STIXResult,
)


def _compute_threat_verdict(
    static: StaticAnalysisResult | None,
    capabilities: CapabilityResult | None,
    evasion: EvasionResult | None,
    similarity: SimilarityResult | None,
    threat_intel: ThreatIntelResult | None,
    unpacking: UnpackingResult | None,
    mitre: MITREResult | None,
) -> tuple[ThreatLevel, float, list[str]]:
    """
    Evidence-based verdict computation.
    Returns (threat_level, confidence, reasoning_list).
    """
    score = 0
    max_score = 0
    reasoning: list[str] = []

    # ── Threat Intelligence (weight: 30) ─────────────────────────────────────
    max_score += 30
    if threat_intel and threat_intel.is_known_malware:
        score += 30
        reasoning.append(
            f"VirusTotal: {threat_intel.virustotal_detections}/{threat_intel.virustotal_total} "
            f"engines detected as malicious"
        )
        if threat_intel.known_family:
            reasoning.append(f"Known malware family: {threat_intel.known_family}")

    # ── Capabilities (weight: 25) ─────────────────────────────────────────────
    max_score += 25
    if capabilities:
        cap_score = 0
        if capabilities.has_injection:
            cap_score += 7
            reasoning.append("Process injection capability detected (CreateRemoteThread/WriteProcessMemory)")
        if capabilities.has_credential_theft:
            cap_score += 6
            reasoning.append("Credential theft capability detected")
        if capabilities.has_keylogging:
            cap_score += 5
            reasoning.append("Keylogging capability detected")
        if capabilities.has_persistence:
            cap_score += 4
            reasoning.append("Persistence mechanisms detected (registry/service)")
        if capabilities.has_ransomware:
            cap_score += 7
            reasoning.append("Ransomware capability detected (file encryption)")
        if capabilities.has_network_beaconing:
            cap_score += 3
            reasoning.append("Network C2 beaconing capability detected")
        score += min(cap_score, 25)

    # ── Evasion (weight: 20) ──────────────────────────────────────────────────
    max_score += 20
    if evasion:
        evasion_score = 0
        if evasion.anti_vm:
            evasion_score += 6
            reasoning.append("Anti-VM detection techniques present")
        if evasion.anti_debug:
            evasion_score += 5
            reasoning.append("Anti-debugging techniques detected")
        if evasion.api_obfuscation:
            evasion_score += 5
            reasoning.append("API obfuscation/hashing detected")
        if evasion.anti_sandbox:
            evasion_score += 4
            reasoning.append("Sandbox evasion techniques detected")
        score += min(evasion_score, 20)

    # ── Similarity (weight: 15) ───────────────────────────────────────────────
    max_score += 15
    if similarity and similarity.top_similarity > 0.5:
        sim_score = int(similarity.top_similarity * 15)
        score += sim_score
        reasoning.append(
            f"High similarity ({similarity.top_similarity:.0%}) to {similarity.top_family} malware family"
        )

    # ── Packing (weight: 10) ──────────────────────────────────────────────────
    max_score += 10
    if unpacking and unpacking.is_packed:
        score += 8
        reasoning.append(
            f"Binary is packed with {unpacking.packer or 'unknown packer'} "
            f"({unpacking.layers} layers)"
        )
    elif static and static.high_entropy_sections:
        score += 5
        reasoning.append(
            f"High entropy sections detected: {', '.join(static.high_entropy_sections)}"
        )

    # Compute confidence
    confidence = score / max_score if max_score > 0 else 0.0

    # Determine threat level
    if confidence >= 0.75:
        threat_level = ThreatLevel.MALICIOUS
    elif confidence >= 0.40:
        threat_level = ThreatLevel.SUSPICIOUS
    elif confidence >= 0.10:
        threat_level = ThreatLevel.SUSPICIOUS
    else:
        threat_level = ThreatLevel.CLEAN

    return threat_level, round(confidence, 3), reasoning


def generate_report(
    job_id: str,
    filename: str,
    analysis_duration: float,
    sample_intake: SampleIntakeResult | None = None,
    static_analysis: StaticAnalysisResult | None = None,
    unpacking: UnpackingResult | None = None,
    capabilities: CapabilityResult | None = None,
    cfg: CFGResult | None = None,
    evasion: EvasionResult | None = None,
    emulation: EmulationResult | None = None,
    similarity: SimilarityResult | None = None,
    clustering: ClusteringResult | None = None,
    threat_intel: ThreatIntelResult | None = None,
    mitre: MITREResult | None = None,
    rag_explanation: RAGExplanation | None = None,
    decompilation: DecompilationResult | None = None,
    yara: YARAResult | None = None,
    attack_navigator: ATTACKNavigatorResult | None = None,
    stix: STIXResult | None = None,
    artifacts: dict | None = None,
    output_dir: Path | None = None,
) -> VigilReport:
    logger.info(f"[Report] Generating final report for job: {job_id}")

    from datetime import datetime, timezone
    timestamp = datetime.now(timezone.utc).isoformat()

    threat_level, confidence, reasoning = _compute_threat_verdict(
        static=static_analysis,
        capabilities=capabilities,
        evasion=evasion,
        similarity=similarity,
        threat_intel=threat_intel,
        unpacking=unpacking,
        mitre=mitre,
    )

    report = VigilReport(
        job_id=job_id,
        filename=filename,
        analysis_timestamp=timestamp,
        analysis_duration_seconds=analysis_duration,
        threat_level=threat_level,
        confidence_score=confidence,
        verdict_reasoning=reasoning,
        sample_intake=sample_intake,
        static_analysis=static_analysis,
        unpacking=unpacking,
        capabilities=capabilities,
        cfg=cfg,
        evasion=evasion,
        emulation=emulation,
        similarity=similarity,
        clustering=clustering,
        threat_intel=threat_intel,
        mitre=mitre,
        rag_explanation=rag_explanation,
        decompilation=decompilation,
        yara=yara,
        attack_navigator=attack_navigator,
        stix=stix,
        artifacts=artifacts or {},
    )

    # Save JSON report
    if output_dir:
        report_path = output_dir / "report.json"
        with open(report_path, "w") as f:
            f.write(report.model_dump_json(indent=2))
        logger.info(f"[Report] Saved to: {report_path}")

    return report
