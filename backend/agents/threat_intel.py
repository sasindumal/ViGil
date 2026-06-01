"""
ViGiL — Agent 10: Threat Intelligence Agent
Queries VirusTotal, MalwareBazaar, AbuseIPDB, AlienVault OTX.
Falls back to mock/demo data when API keys are absent.
"""
from __future__ import annotations

import time
from typing import Optional

import httpx
from loguru import logger

from config import settings
from models import ThreatIntelResult


# ─── Mock demo data ──────────────────────────────────────────────────────────
MOCK_VT_RESPONSE = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 42,
                "undetected": 23,
                "harmless": 3,
                "suspicious": 5,
                "total": 73,
            },
            "popular_threat_classification": {
                "suggested_threat_label": "trojan.genericstealer/redline"
            },
        }
    }
}

MOCK_MBZ_RESPONSE = {
    "data": [
        {
            "tags": ["stealer", "credential-theft", "redline"],
            "file_name": "sample.exe",
            "reporter": "abuse.ch",
            "signature": "RedLine",
        }
    ]
}


async def _query_virustotal(sha256: str) -> Optional[dict]:
    if not settings.virustotal_api_key:
        return None
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": settings.virustotal_api_key},
            )
            if resp.status_code == 200:
                return resp.json()
            logger.warning(f"[ThreatIntel] VirusTotal returned {resp.status_code}")
    except Exception as e:
        logger.warning(f"[ThreatIntel] VirusTotal error: {e}")
    return None


async def _query_malwarebazaar(sha256: str) -> Optional[dict]:
    if not settings.malwarebazaar_api_key:
        return None
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": sha256},
                headers={"Auth-Key": settings.malwarebazaar_api_key},
            )
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        logger.warning(f"[ThreatIntel] MalwareBazaar error: {e}")
    return None


async def _query_abuseipdb(ip: str) -> Optional[dict]:
    if not settings.abuseipdb_api_key or not ip:
        return None
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            )
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        logger.warning(f"[ThreatIntel] AbuseIPDB error: {e}")
    return None


async def _query_otx(sha256: str) -> Optional[dict]:
    if not settings.alienvault_otx_api_key:
        return None
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general",
                headers={"X-OTX-API-KEY": settings.alienvault_otx_api_key},
            )
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        logger.warning(f"[ThreatIntel] OTX error: {e}")
    return None


async def run_threat_intel(
    sha256: str,
    ips: list[str] = None,
    domains: list[str] = None,
) -> ThreatIntelResult:
    logger.info(f"[ThreatIntel] Looking up: {sha256[:16]}...")

    demo_mode = not settings.threat_intel_enabled

    if demo_mode:
        logger.info("[ThreatIntel] Demo mode — using mock responses")
        return ThreatIntelResult(
            virustotal_detections=MOCK_VT_RESPONSE["data"]["attributes"]["last_analysis_stats"]["malicious"],
            virustotal_total=MOCK_VT_RESPONSE["data"]["attributes"]["last_analysis_stats"]["total"],
            virustotal_verdict="trojan.genericstealer/redline",
            malwarebazaar_tags=["stealer", "credential-theft", "redline"],
            malwarebazaar_family="RedLine",
            known_family="RedLine",
            campaign="RedLine Stealer Campaign 2024",
            threat_actor="Unknown",
            is_known_malware=True,
            demo_mode=True,
        )

    # Real API queries
    vt_result = await _query_virustotal(sha256)
    mbz_result = await _query_malwarebazaar(sha256)
    otx_result = await _query_otx(sha256)

    # Parse results
    vt_detections = 0
    vt_total = 0
    vt_verdict = None
    if vt_result:
        stats = vt_result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        vt_detections = stats.get("malicious", 0)
        vt_total = sum(stats.values())
        label = vt_result.get("data", {}).get("attributes", {}).get(
            "popular_threat_classification", {}
        ).get("suggested_threat_label")
        vt_verdict = label

    mbz_tags = []
    mbz_family = None
    if mbz_result and mbz_result.get("data"):
        entry = mbz_result["data"][0]
        mbz_tags = entry.get("tags", [])
        mbz_family = entry.get("signature")

    otx_pulses = []
    if otx_result:
        for pulse in otx_result.get("pulse_info", {}).get("pulses", [])[:10]:
            otx_pulses.append(pulse.get("name", ""))

    known_family = mbz_family or (vt_verdict.split("/")[-1].title() if vt_verdict else None)

    return ThreatIntelResult(
        virustotal_detections=vt_detections,
        virustotal_total=vt_total,
        virustotal_verdict=vt_verdict,
        malwarebazaar_tags=mbz_tags,
        malwarebazaar_family=mbz_family,
        otx_pulses=otx_pulses,
        known_family=known_family,
        is_known_malware=vt_detections > 5,
        demo_mode=False,
    )
