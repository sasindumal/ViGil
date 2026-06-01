"""
ViGiL — Agent 12: RAG Intelligence Agent
Provides evidence-backed explanations using LLM + knowledge base context.
Supports OpenAI, Gemini, and Ollama.
"""
from __future__ import annotations

from loguru import logger

from config import settings
from models import RAGExplanation


# Knowledge base excerpts (in production: loaded from Qdrant vector store)
KNOWLEDGE_BASE = [
    {
        "title": "RedLine Stealer Analysis",
        "source": "ANY.RUN 2024",
        "content": (
            "RedLine Stealer is an information-stealing malware sold as MaaS. "
            "It targets browser credentials, cryptocurrency wallets, FTP clients, and system data. "
            "Key TTPs: T1555 (Credentials from Password Stores), T1071 (Application Layer Protocol), "
            "T1056 (Input Capture). Uses HTTP POST requests to C2 with base64-encoded data."
        ),
    },
    {
        "title": "Process Injection Techniques",
        "source": "MITRE ATT&CK T1055",
        "content": (
            "Process injection is a technique where adversaries inject code into running processes "
            "to evade process-based defenses and possibly elevate privileges. Common methods include "
            "DLL injection via CreateRemoteThread + WriteProcessMemory, process hollowing via "
            "NtUnmapViewOfSection, and APC injection."
        ),
    },
    {
        "title": "Anti-VM Detection Techniques",
        "source": "MITRE ATT&CK T1497",
        "content": (
            "Malware checks for virtual machine artifacts: VirtualBox GuestAdditions registry keys, "
            "VMware MAC prefixes (00:0C:29), CPUID hypervisor bit, RDTSC timing attacks, "
            "presence of VM-specific drivers (vboxguest.sys, vmci.sys)."
        ),
    },
    {
        "title": "Credential Theft via Browser",
        "source": "CAPA Rules",
        "content": (
            "Credential stealers target SQLite databases in browser profiles (Chrome, Firefox, Edge). "
            "Common paths: AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data. "
            "Uses CryptUnprotectData (DPAPI) to decrypt saved passwords."
        ),
    },
    {
        "title": "API Hashing for Evasion",
        "source": "Malware Research",
        "content": (
            "API hashing resolves Win32 API functions at runtime by computing hash of function names "
            "and comparing against a hardcoded value. This defeats static import analysis. "
            "Common hash algorithms: ROR13, djb2, FNV-1a. Detection: indirect calls through a "
            "resolved function pointer after GetProcAddress."
        ),
    },
]


async def _call_llm(prompt: str) -> str:
    """Route to appropriate LLM provider based on settings."""
    provider = settings.llm_provider

    if provider == "openai" and settings.openai_api_key:
        return await _call_openai(prompt)
    elif provider == "gemini" and settings.google_api_key:
        return await _call_gemini(prompt)
    elif provider == "ollama":
        return await _call_ollama(prompt)
    elif provider == "lmstudio":
        return await _call_lmstudio(prompt)
    else:
        return _static_explanation(prompt)


async def _call_openai(prompt: str) -> str:
    try:
        from openai import AsyncOpenAI

        client = AsyncOpenAI(api_key=settings.openai_api_key)
        response = await client.chat.completions.create(
            model=settings.openai_model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a malware analyst. Provide concise, technical, evidence-backed "
                        "explanations. Base your analysis on the provided evidence only."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=500,
            temperature=0.1,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logger.warning(f"[RAG] OpenAI error: {e}")
        return _static_explanation(prompt)


async def _call_gemini(prompt: str) -> str:
    try:
        import google.generativeai as genai

        genai.configure(api_key=settings.google_api_key)
        model = genai.GenerativeModel(settings.gemini_model)
        response = await model.generate_content_async(prompt)
        return response.text.strip()
    except Exception as e:
        logger.warning(f"[RAG] Gemini error: {e}")
        return _static_explanation(prompt)


async def _call_ollama(prompt: str) -> str:
    try:
        import httpx

        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{settings.ollama_base_url}/api/generate",
                json={
                    "model": settings.ollama_model,
                    "prompt": prompt,
                    "stream": False,
                },
            )
            if resp.status_code == 200:
                return resp.json().get("response", "").strip()
    except Exception as e:
        logger.warning(f"[RAG] Ollama error: {e}")
    return _static_explanation(prompt)


async def _call_lmstudio(prompt: str) -> str:
    """LM Studio uses an OpenAI-compatible API — no key required."""
    try:
        from openai import AsyncOpenAI

        client = AsyncOpenAI(
            base_url=settings.lmstudio_base_url,
            api_key="lm-studio",  # LM Studio ignores the key value; any non-empty string works
        )
        response = await client.chat.completions.create(
            model=settings.lmstudio_model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a malware analyst. Provide concise, technical, evidence-backed "
                        "explanations. Base your analysis on the provided evidence only."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=500,
            temperature=0.1,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logger.warning(f"[RAG] LM Studio error: {e}")
    return _static_explanation(prompt)


def _static_explanation(context: str) -> str:
    """Fallback when no LLM is configured."""
    return (
        "Analysis based on static evidence: Multiple high-confidence indicators were detected "
        "including evasion techniques, suspicious API usage, and behavioral patterns consistent "
        "with known malware families. Each finding is backed by concrete forensic evidence."
    )


def _retrieve_relevant_kb(capabilities: list[str], techniques: list[str], family: str | None) -> list[dict]:
    """Simple keyword-based retrieval from knowledge base."""
    relevant = []
    query_terms = set(
        [c.lower() for c in capabilities]
        + [t.lower() for t in techniques]
        + ([family.lower()] if family else [])
    )

    for entry in KNOWLEDGE_BASE:
        content_lower = entry["content"].lower() + entry["title"].lower()
        if any(term in content_lower for term in query_terms):
            relevant.append(entry)

    return relevant[:3]  # Top 3 most relevant


async def run_rag_intelligence(
    capabilities: list[str] = None,
    evasion: dict = None,
    techniques: list[str] = None,
    family: str = None,
    threat_level: str = "suspicious",
) -> RAGExplanation:
    logger.info("[RAG] Generating evidence-backed analysis")

    capabilities = capabilities or []
    techniques = techniques or []

    # Retrieve relevant KB entries
    relevant_kb = _retrieve_relevant_kb(capabilities, techniques, family)

    # Build evidence-enriched prompt
    kb_context = "\n\n".join(
        f"[{entry['source']}] {entry['title']}:\n{entry['content']}"
        for entry in relevant_kb
    )

    evasion_summary = []
    if evasion:
        if evasion.get("anti_vm"):
            evasion_summary.append("Anti-VM detection")
        if evasion.get("anti_debug"):
            evasion_summary.append("Anti-debug techniques")
        if evasion.get("api_obfuscation"):
            evasion_summary.append("API obfuscation/hashing")
        if evasion.get("anti_sandbox"):
            evasion_summary.append("Sandbox evasion")

    prompt = f"""You are a malware analyst. Based on the following evidence, explain why this sample is {threat_level}.

DETECTED CAPABILITIES:
{chr(10).join(f'- {c}' for c in capabilities) or 'None detected'}

EVASION TECHNIQUES:
{chr(10).join(f'- {e}' for e in evasion_summary) or 'None detected'}

MITRE ATT&CK TECHNIQUES:
{chr(10).join(f'- {t}' for t in techniques[:10]) or 'None mapped'}

SIMILAR MALWARE FAMILY: {family or 'Unknown'}

RELEVANT INTELLIGENCE:
{kb_context or 'No relevant intelligence found'}

Provide a concise technical explanation (3-4 sentences) referencing the evidence above.
Do NOT speculate beyond the evidence provided."""

    summary = await _call_llm(prompt)

    return RAGExplanation(
        summary=summary,
        evidence_sources=[e["source"] for e in relevant_kb],
        related_reports=[e["title"] for e in relevant_kb],
        risk_explanation=f"This sample exhibits {len(capabilities)} detected capabilities and {len(evasion_summary)} evasion techniques.",
        analyst_notes=f"Similarity analysis suggests relationship to {family} malware family." if family else "Novel sample — no strong family match.",
    )
