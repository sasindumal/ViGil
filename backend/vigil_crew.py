"""
ViGiL — CrewAI Agentic Reasoning Engine
Five specialized LLM agents collaborate to produce a final verdict.

Architecture:
  Phase 1 (caller): deterministic tools collect raw evidence
  Phase 2 (this module): CrewAI agents reason over evidence → AgenticVerdict

Process: Hierarchical — a manager LLM delegates tasks and can reassign.
LLM: LM Studio (OpenAI-compatible) via LiteLLM.
"""
from __future__ import annotations

import json
import re
import textwrap
from typing import Any

from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from langchain_openai import ChatOpenAI
from loguru import logger

from config import settings
from models import (
    AgentThought, AgenticVerdict, ReasoningChain, ThreatLevel,
)


# ─────────────────────────────────────────────────────────────────────────────
# LLM Factory — LM Studio via OpenAI-compatible endpoint
# ─────────────────────────────────────────────────────────────────────────────

def _build_llm() -> ChatOpenAI:
    """Return a LangChain LLM pointed at the configured provider."""
    provider = settings.llm_provider.lower()

    if provider == "lmstudio":
        return ChatOpenAI(
            model=settings.lmstudio_model or "local-model",
            base_url=settings.lmstudio_base_url,
            api_key="lm-studio",          # LM Studio ignores this
            temperature=0.2,
            max_tokens=4096,
        )
    elif provider == "ollama":
        return ChatOpenAI(
            model=f"ollama/{settings.ollama_model}",
            base_url=settings.ollama_base_url,
            api_key="ollama",
            temperature=0.2,
            max_tokens=4096,
        )
    elif provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(
            model=settings.gemini_model,
            google_api_key=settings.gemini_api_key,
            temperature=0.2,
        )
    else:  # openai default
        return ChatOpenAI(
            model=settings.openai_model,
            api_key=settings.openai_api_key,
            temperature=0.2,
            max_tokens=4096,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Evidence Serializer
# ─────────────────────────────────────────────────────────────────────────────

def _format_evidence(evidence: dict[str, Any]) -> str:
    """Convert raw evidence dict into a compact analyst-readable context block."""
    sample = evidence.get("sample", {})
    static = evidence.get("static", {})
    caps = evidence.get("capabilities", [])
    evasion = evidence.get("evasion", {})
    emulation = evidence.get("emulation", {})
    intel = evidence.get("threat_intel", {})
    mitre = evidence.get("mitre_techniques", [])
    similarity = evidence.get("similarity", {})

    return textwrap.dedent(f"""
    === SAMPLE METADATA ===
    File: {evidence.get('filename', 'unknown')}
    SHA256: {sample.get('sha256', 'N/A')}
    Architecture: {sample.get('arch', 'N/A')}
    Size: {sample.get('file_size', 0):,} bytes
    Compile time: {sample.get('compile_timestamp', 'N/A')}
    .NET: {sample.get('is_dotnet', False)}

    === STATIC ANALYSIS ===
    Sections: {len(static.get('sections', []))} | High-entropy: {static.get('high_entropy_sections', [])}
    Imports: {len(static.get('imports', []))} DLLs
    Suspicious strings: {static.get('suspicious_strings', [])[:15]}
    URLs: {static.get('urls', [])[:10]}
    IPs: {static.get('ips', [])[:10]}
    Domains: {static.get('domains', [])[:10]}
    Has overlay: {static.get('has_overlay', False)}
    Has TLS callbacks: {static.get('has_tls_callbacks', False)}

    === CAPABILITIES (CAPA) ===
    {json.dumps(caps[:30], indent=2)}

    === EVASION ===
    Anti-VM: {evasion.get('anti_vm', False)} — {evasion.get('anti_vm_techniques', [])}
    Anti-Debug: {evasion.get('anti_debug', False)} — {evasion.get('anti_debug_techniques', [])}
    Anti-Sandbox: {evasion.get('anti_sandbox', False)}
    API Obfuscation: {evasion.get('api_obfuscation', False)}
    Evasion Score: {evasion.get('evasion_score', 0)}/100

    === EMULATION ===
    API calls: {emulation.get('api_calls', [])[:20]}
    Network: {emulation.get('network_connections', [])[:5]}
    Domains contacted: {emulation.get('domains_contacted', [])}
    Files created: {emulation.get('files_created', [])[:10]}
    Registry keys created: {emulation.get('registry_keys_created', [])[:10]}
    Processes created: {emulation.get('processes_created', [])}

    === THREAT INTELLIGENCE ===
    VirusTotal: {intel.get('virustotal_detections', 0)}/{intel.get('virustotal_total', 0)} detections
    VT verdict: {intel.get('virustotal_verdict', 'N/A')}
    Known family: {intel.get('known_family', 'Unknown')}
    MalwareBazaar tags: {intel.get('malwarebazaar_tags', [])}
    OTX pulses: {intel.get('otx_pulses', [])[:5]}
    Demo mode: {intel.get('demo_mode', True)}

    === MITRE ATT&CK TECHNIQUES ===
    {json.dumps([t.get('technique_id', '') + ' ' + t.get('technique_name', '') for t in mitre[:20]], indent=2)}

    === SIMILARITY ===
    Top family: {similarity.get('top_family', 'Unknown')}
    Top similarity: {similarity.get('top_similarity', 0):.1%}
    """).strip()


# ─────────────────────────────────────────────────────────────────────────────
# CrewAI Agents & Tasks
# ─────────────────────────────────────────────────────────────────────────────

def build_crew(evidence_context: str, llm: ChatOpenAI) -> Crew:
    """Construct the ViGiL CrewAI crew with 5 specialized agents."""

    # ── Agent 1: Static PE Analyst ────────────────────────────────────────────
    static_analyst = Agent(
        role="Senior PE Reverse Engineer",
        goal=(
            "Analyze PE structure, import tables, section entropy, strings, and overlays. "
            "Identify structural anomalies that indicate packing, obfuscation, or malicious intent."
        ),
        backstory=(
            "You have 15 years of experience in low-level Windows internals and reverse engineering. "
            "You are an expert at reading PE headers, import tables, and recognizing obfuscation patterns "
            "from entropy spikes, suspicious section names, and unusual import sets. "
            "You think in terms of evidence — every conclusion must cite specific indicators."
        ),
        llm=llm,
        verbose=settings.crewai_verbose,
        allow_delegation=False,
        max_iter=3,
    )

    # ── Agent 2: Behavioral Analyst ───────────────────────────────────────────
    behavioral_analyst = Agent(
        role="Behavioral Malware Analyst",
        goal=(
            "Reason about runtime behavior from emulation traces, API call sequences, "
            "evasion detections, and capability indicators. Determine what the malware does when executed."
        ),
        backstory=(
            "You specialize in dynamic malware analysis — sandbox emulation, API hooking, and behavioral patterns. "
            "You recognize anti-analysis tricks like CPUID checks, timing attacks, and debugger detection. "
            "You map API call sequences to behaviors: persistence, C2 communication, data exfiltration, "
            "lateral movement. You cite specific API calls and emulation events as evidence."
        ),
        llm=llm,
        verbose=settings.crewai_verbose,
        allow_delegation=False,
        max_iter=3,
    )

    # ── Agent 3: Threat Intelligence Analyst ──────────────────────────────────
    intel_analyst = Agent(
        role="Cyber Threat Intelligence Analyst",
        goal=(
            "Attribute the sample to known malware families, threat actors, and campaigns. "
            "Cross-reference VirusTotal detections, MalwareBazaar tags, MITRE ATT&CK techniques, "
            "and similarity matches to produce a confident attribution."
        ),
        backstory=(
            "You are a CTI analyst with deep expertise in threat actor TTPs, malware family taxonomies, "
            "and OSINT. You track APT groups, ransomware gangs, and commodity malware families. "
            "You are skilled at reading VT detections to extract family names even from partial hits. "
            "You map ATT&CK technique clusters to specific threat actors."
        ),
        llm=llm,
        verbose=settings.crewai_verbose,
        allow_delegation=False,
        max_iter=3,
    )

    # ── Agent 4: Verdict Analyst ──────────────────────────────────────────────
    verdict_analyst = Agent(
        role="Lead Malware Analyst",
        goal=(
            "Synthesize findings from the static, behavioral, and threat intel analysts into a final verdict. "
            "Assign a threat level (clean/suspicious/malicious), confidence score, and list key evidence. "
            "Output must be structured JSON."
        ),
        backstory=(
            "You are the senior analyst who reviews all team findings and makes the final call. "
            "You weigh conflicting evidence, apply Occam's razor, and produce a verdict that a SOC team "
            "can act on immediately. You are calibrated — you don't overstate confidence. "
            "You always provide your top 5 key evidence items that drove the verdict."
        ),
        llm=llm,
        verbose=settings.crewai_verbose,
        allow_delegation=False,
        max_iter=3,
    )

    # ── Agent 5: Report Writer ────────────────────────────────────────────────
    report_writer = Agent(
        role="Forensic Report Author",
        goal=(
            "Produce a concise, structured forensic report for SOC analysts and incident responders. "
            "Include executive summary, technical findings, and recommended actions."
        ),
        backstory=(
            "You write the final-form reports that go to incident response teams, SOC leads, and CISOs. "
            "Your reports are clear, evidence-cited, and actionable. "
            "You are concise — no filler, no speculation without evidence. "
            "You always include recommended containment and eradication steps."
        ),
        llm=llm,
        verbose=settings.crewai_verbose,
        allow_delegation=False,
        max_iter=2,
    )

    # ── Tasks ─────────────────────────────────────────────────────────────────

    task_static = Task(
        description=textwrap.dedent(f"""
            Analyze the static PE evidence below and produce a structured assessment.

            Focus on:
            - Section entropy and what it implies (packed? encrypted payload?)
            - Import table: which DLLs/APIs suggest malicious capability?
            - Suspicious strings: C2 indicators, registry paths, mutex names
            - Structural anomalies: overlays, TLS callbacks, unusual headers

            EVIDENCE:
            {evidence_context}

            Provide your findings as:
            FINDINGS: <your detailed analysis>
            KEY_INDICATORS: <comma-separated list of top 5 specific indicators>
            CONFIDENCE: <0.0-1.0>
        """),
        expected_output="Structured static analysis assessment with findings, key indicators, and confidence score.",
        agent=static_analyst,
    )

    task_behavioral = Task(
        description=textwrap.dedent(f"""
            Analyze the behavioral evidence (emulation, evasion, capabilities) and determine
            what this sample does at runtime.

            Focus on:
            - API call sequences: what behavior do they indicate?
            - Evasion: what is the malware trying to hide from?
            - Network activity: C2 beaconing patterns?
            - Persistence mechanisms
            - Capability indicators from CAPA

            EVIDENCE:
            {evidence_context}

            Context from static analysis: {{static_analysis_output}}

            Provide:
            FINDINGS: <behavioral assessment>
            KEY_INDICATORS: <top 5 behavioral indicators>
            CONFIDENCE: <0.0-1.0>
        """),
        expected_output="Behavioral analysis with runtime behavior assessment, key indicators, and confidence.",
        agent=behavioral_analyst,
        context=[task_static],
    )

    task_intel = Task(
        description=textwrap.dedent(f"""
            Use the threat intelligence data and MITRE ATT&CK mapping to attribute this sample.

            Focus on:
            - VT family names from detections
            - MalwareBazaar tags and classification
            - MITRE technique clusters — do they match a known threat actor?
            - Similarity matches to known families
            - OTX pulse context

            EVIDENCE:
            {evidence_context}

            Context from prior analysis: {{static_analysis_output}} {{behavioral_analysis_output}}

            Provide:
            FINDINGS: <attribution and family identification>
            KEY_INDICATORS: <top 5 intel indicators>
            CONFIDENCE: <0.0-1.0>
            FAMILY: <best family name or "Unknown">
            THREAT_ACTOR: <threat actor or "Unknown">
        """),
        expected_output="Threat attribution with family, threat actor, key intelligence indicators, and confidence.",
        agent=intel_analyst,
        context=[task_static, task_behavioral],
    )

    task_verdict = Task(
        description=textwrap.dedent(f"""
            You have received assessments from the static analyst, behavioral analyst,
            and threat intel analyst. Synthesize them into a final verdict.

            Produce a JSON verdict in EXACTLY this format:
            {{
              "threat_level": "clean|suspicious|malicious",
              "confidence_score": 0.0-1.0,
              "malware_family": "family name or null",
              "malware_type": "ransomware|trojan|rat|stealer|dropper|worm|adware|pua|unknown or null",
              "threat_actor": "actor name or null",
              "key_evidence": ["evidence 1", "evidence 2", "evidence 3", "evidence 4", "evidence 5"],
              "recommended_actions": ["action 1", "action 2", "action 3"]
            }}

            Rules:
            - malicious if VT >= 5 detections OR CAPA shows credential theft/ransomware/injection
            - suspicious if evasion score >= 30 OR high entropy sections + few imports
            - clean only if strong evidence of legitimate software
        """),
        expected_output="JSON verdict object with threat_level, confidence, family, type, actor, evidence, and actions.",
        agent=verdict_analyst,
        context=[task_static, task_behavioral, task_intel],
    )

    task_report = Task(
        description=textwrap.dedent(f"""
            Write the executive summary section of the forensic report.

            Using all analyst findings, produce:
            1. A 2-3 sentence executive summary for management
            2. Key technical findings (bullet list, max 7)
            3. Recommended immediate actions (bullet list, max 5)

            Be concise, evidence-based, and actionable.
            File analyzed: {evidence_context.split(chr(10))[0]}
        """),
        expected_output="Executive summary, technical findings, and recommended actions for the forensic report.",
        agent=report_writer,
        context=[task_static, task_behavioral, task_intel, task_verdict],
    )

    # ── Manager LLM (hierarchical process) ───────────────────────────────────
    manager_llm = _build_llm()

    return Crew(
        agents=[static_analyst, behavioral_analyst, intel_analyst, verdict_analyst, report_writer],
        tasks=[task_static, task_behavioral, task_intel, task_verdict, task_report],
        process=Process.hierarchical,
        manager_llm=manager_llm,
        verbose=settings.crewai_verbose,
        memory=False,           # no persistent memory — each analysis is independent
        embedder=None,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Result Parser
# ─────────────────────────────────────────────────────────────────────────────

def _parse_verdict_from_crew_output(crew_output: str, task_outputs: list) -> AgenticVerdict:
    """Parse CrewAI task outputs into a structured AgenticVerdict."""

    def _extract_field(text: str, key: str) -> str:
        m = re.search(rf"{key}:\s*(.+?)(?:\n[A-Z_]+:|$)", text, re.DOTALL | re.IGNORECASE)
        return m.group(1).strip() if m else ""

    def _extract_indicators(text: str) -> list[str]:
        raw = _extract_field(text, "KEY_INDICATORS")
        if not raw:
            return []
        return [i.strip() for i in re.split(r"[,\n•\-]", raw) if i.strip()][:7]

    def _extract_confidence(text: str) -> float:
        raw = _extract_field(text, "CONFIDENCE")
        try:
            return max(0.0, min(1.0, float(raw)))
        except (ValueError, TypeError):
            return 0.5

    # Extract per-agent thoughts
    thoughts = []
    roles = [
        "Senior PE Reverse Engineer",
        "Behavioral Malware Analyst",
        "Cyber Threat Intelligence Analyst",
        "Lead Malware Analyst",
        "Forensic Report Author",
    ]
    for i, out in enumerate(task_outputs or []):
        text = str(out.raw if hasattr(out, "raw") else out)
        role = roles[i] if i < len(roles) else f"Agent {i+1}"
        thoughts.append(AgentThought(
            agent_role=role,
            findings=_extract_field(text, "FINDINGS") or text[:500],
            key_indicators=_extract_indicators(text),
            confidence=_extract_confidence(text),
        ))

    # Parse structured JSON verdict from task 4 (verdict_analyst)
    threat_level = ThreatLevel.UNKNOWN
    confidence = 0.5
    family = None
    malware_type = None
    threat_actor = None
    key_evidence: list[str] = []
    recommended: list[str] = []

    verdict_text = str(task_outputs[3].raw if len(task_outputs) > 3 else "")
    try:
        # Extract JSON block
        json_match = re.search(r"\{[\s\S]+\}", verdict_text)
        if json_match:
            v = json.loads(json_match.group(0))
            tl = v.get("threat_level", "unknown").lower()
            threat_level = ThreatLevel(tl) if tl in ThreatLevel._value2member_map_ else ThreatLevel.UNKNOWN
            confidence = float(v.get("confidence_score", 0.5))
            family = v.get("malware_family")
            malware_type = v.get("malware_type")
            threat_actor = v.get("threat_actor")
            key_evidence = v.get("key_evidence", [])[:5]
            recommended = v.get("recommended_actions", [])[:5]
    except (json.JSONDecodeError, ValueError, AttributeError) as e:
        logger.warning(f"[CrewAI] Could not parse verdict JSON: {e}")
        # Fallback: extract from text
        if "malicious" in verdict_text.lower():
            threat_level = ThreatLevel.MALICIOUS
        elif "suspicious" in verdict_text.lower():
            threat_level = ThreatLevel.SUSPICIOUS

    # Executive summary from report writer
    exec_summary = ""
    if len(task_outputs) > 4:
        exec_summary = str(task_outputs[4].raw if hasattr(task_outputs[4], "raw") else task_outputs[4])[:1000]

    chain = ReasoningChain(
        static_analysis_thought=thoughts[0] if len(thoughts) > 0 else None,
        behavioral_thought=thoughts[1] if len(thoughts) > 1 else None,
        threat_intel_thought=thoughts[2] if len(thoughts) > 2 else None,
        verdict_thought=thoughts[3] if len(thoughts) > 3 else None,
        report_thought=thoughts[4] if len(thoughts) > 4 else None,
    )

    return AgenticVerdict(
        threat_level=threat_level,
        confidence_score=confidence,
        malware_family=family,
        malware_type=malware_type,
        threat_actor=threat_actor,
        executive_summary=exec_summary,
        key_evidence=key_evidence,
        recommended_actions=recommended,
        reasoning_chain=chain,
        llm_provider=settings.llm_provider,
        llm_model=getattr(settings, "lmstudio_model", "unknown"),
        crew_process="hierarchical",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public Entry Point
# ─────────────────────────────────────────────────────────────────────────────

async def run_crew(evidence: dict[str, Any]) -> AgenticVerdict:
    """
    Run the CrewAI hierarchical crew over the collected evidence.
    Returns an AgenticVerdict with the LLM reasoning chain.
    """
    import asyncio

    logger.info("[CrewAI] Starting hierarchical agentic reasoning...")
    llm = _build_llm()
    evidence_context = _format_evidence(evidence)
    c = build_crew(evidence_context, llm)

    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, c.kickoff)

        task_outputs = result.tasks_output if hasattr(result, "tasks_output") else []
        verdict = _parse_verdict_from_crew_output(str(result), task_outputs)
        logger.info(f"[CrewAI] Verdict: {verdict.threat_level.value} ({verdict.confidence_score:.0%} confidence)")
        return verdict

    except Exception as e:
        logger.error(f"[CrewAI] Crew failed: {e}")
        return AgenticVerdict(
            threat_level=ThreatLevel.UNKNOWN,
            confidence_score=0.0,
            executive_summary=f"Agentic reasoning failed: {str(e)[:200]}",
            llm_provider=settings.llm_provider,
            crew_process="hierarchical",
        )
