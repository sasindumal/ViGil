"""
ViGiL — Agent 8: Similarity Analysis Agent
Compares the sample against known malware families using FAISS vector similarity.
Generates embeddings from capabilities, APIs, strings, ATT&CK techniques.
"""
from __future__ import annotations

import json
import numpy as np
from pathlib import Path
from typing import Optional

from loguru import logger

from models import SimilarityResult, SimilarityMatch


# Pre-seeded malware family profiles (synthetic for demo)
# In production: populated from real malware corpus
MALWARE_FAMILY_PROFILES = {
    "RedLine": {
        "capabilities": ["credential theft", "network beaconing", "keylogging"],
        "imports": ["InternetOpenUrl", "GetClipboardData", "CredEnumerate", "CryptDecrypt"],
        "techniques": ["T1555", "T1056", "T1071", "T1113"],
        "strings": ["stealer", "clipboard", "password", "browser"],
    },
    "Lumma": {
        "capabilities": ["credential theft", "network beaconing", "discovery"],
        "imports": ["InternetConnect", "WinHttpOpen", "RegQueryValueEx"],
        "techniques": ["T1555", "T1071", "T1082"],
        "strings": ["lumma", "C2", "exfil", "wallet", "browser"],
    },
    "AgentTesla": {
        "capabilities": ["keylogging", "credential theft", "network beaconing"],
        "imports": ["GetAsyncKeyState", "SetWindowsHookEx", "SmtpClient"],
        "techniques": ["T1056", "T1555", "T1071"],
        "strings": ["smtp", "keylog", "screenshot", "password"],
    },
    "AsyncRAT": {
        "capabilities": ["remote access", "persistence", "process injection"],
        "imports": ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx"],
        "techniques": ["T1059", "T1547", "T1055"],
        "strings": ["async", "RAT", "remote", "powershell"],
    },
    "Emotet": {
        "capabilities": ["network beaconing", "persistence", "discovery"],
        "imports": ["InternetConnect", "RegSetValueEx", "CreateService"],
        "techniques": ["T1547", "T1071", "T1082"],
        "strings": ["emotet", "loader", "macro", "document"],
    },
    "Cobalt Strike": {
        "capabilities": ["process injection", "network beaconing", "persistence"],
        "imports": ["CreateRemoteThread", "VirtualAlloc", "WinHttpConnect"],
        "techniques": ["T1055", "T1071", "T1547", "T1083"],
        "strings": ["beacon", "pipe", "staging", "shellcode"],
    },
    "Ransomware_Generic": {
        "capabilities": ["ransomware", "discovery", "network beaconing"],
        "imports": ["CryptEncrypt", "FindFirstFile", "DeleteFile"],
        "techniques": ["T1486", "T1083", "T1490"],
        "strings": ["encrypt", "ransom", ".locked", "bitcoin", "decrypt"],
    },
}


def _feature_vector(
    capabilities: list[str],
    imports: list[str],
    techniques: list[str],
    strings: list[str],
) -> np.ndarray:
    """
    Build a simple bag-of-features vector from known indicators.
    In production: use sentence-transformers for semantic embeddings.
    """
    all_features = set()
    for profile in MALWARE_FAMILY_PROFILES.values():
        all_features.update(profile["capabilities"])
        all_features.update(profile["imports"])
        all_features.update(profile["techniques"])
        all_features.update(profile["strings"])

    feature_list = sorted(all_features)
    sample_features = set(
        [c.lower() for c in capabilities]
        + [i.lower() for i in imports]
        + [t.lower() for t in techniques]
        + [s.lower() for s in strings]
    )

    vec = np.array(
        [1.0 if feat.lower() in sample_features else 0.0 for feat in feature_list],
        dtype=np.float32,
    )
    norm = np.linalg.norm(vec)
    return vec / norm if norm > 0 else vec


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(np.dot(a, b) / (norm_a * norm_b))


def run_similarity_analysis(
    capabilities: list[str] = None,
    imports: list[str] = None,
    techniques: list[str] = None,
    strings: list[str] = None,
) -> SimilarityResult:
    logger.info("[Similarity] Computing family similarity scores")

    capabilities = capabilities or []
    imports = imports or []
    techniques = techniques or []
    strings = strings or []

    sample_vec = _feature_vector(capabilities, imports, techniques, strings)
    embedding_features = [
        f for f in ["capabilities", "imports", "techniques", "strings"]
        if locals()[f]
    ]

    matches: list[SimilarityMatch] = []

    for family, profile in MALWARE_FAMILY_PROFILES.items():
        family_vec = _feature_vector(
            profile["capabilities"],
            profile["imports"],
            profile["techniques"],
            profile["strings"],
        )
        score = _cosine_similarity(sample_vec, family_vec)
        if score > 0.1:
            matches.append(SimilarityMatch(
                family=family,
                similarity=round(score, 3),
                source="faiss-demo",
            ))

    # Sort by similarity descending
    matches.sort(key=lambda x: x.similarity, reverse=True)
    top_matches = matches[:5]

    top_family = top_matches[0].family if top_matches else None
    top_similarity = top_matches[0].similarity if top_matches else 0.0

    return SimilarityResult(
        matches=top_matches,
        top_family=top_family,
        top_similarity=top_similarity,
        embedding_features=embedding_features,
    )
