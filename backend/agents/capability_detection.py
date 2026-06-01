"""
ViGiL — Agent 4: Capability Detection Agent
Uses CAPA to identify malware capabilities, with mock fallback for demo.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Optional

from loguru import logger

from models import CapabilityResult


CAPABILITY_KEYWORDS = {
    "credential theft": ["credential", "password", "credential-theft", "lsass", "ntlm", "kerberos"],
    "keylogging": ["keylog", "keystroke", "GetAsyncKeyState", "SetWindowsHookEx"],
    "persistence": ["persistence", "registry run", "startup", "autorun", "service"],
    "ransomware": ["encrypt", "ransom", "cipher", "AES", "RSA"],
    "process injection": ["inject", "remote thread", "WriteProcessMemory", "process-injection"],
    "network beaconing": ["beacon", "C2", "command and control", "http request", "network"],
    "discovery": ["enumerate", "discover", "system info", "process list", "file system"],
}


def _run_capa(file_path: Path) -> Optional[dict]:
    """Run CAPA binary and parse JSON output."""
    try:
        result = subprocess.run(
            ["capa", "--json", str(file_path)],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
        logger.warning(f"[CAPA] Non-zero exit: {result.returncode}")
    except FileNotFoundError:
        logger.warning("[CAPA] capa binary not found — using heuristic analysis")
    except subprocess.TimeoutExpired:
        logger.warning("[CAPA] CAPA timed out")
    except json.JSONDecodeError as e:
        logger.warning(f"[CAPA] JSON parse error: {e}")
    return None


def _parse_capa_output(capa_json: dict) -> list[str]:
    """Extract capability names from CAPA JSON output."""
    caps = []
    try:
        for rule_name, rule_data in capa_json.get("rules", {}).items():
            if rule_data.get("matches"):
                caps.append(rule_name)
    except Exception as e:
        logger.debug(f"[CAPA] Parse error: {e}")
    return caps


def _infer_capabilities_from_imports(imports: list[dict]) -> list[str]:
    """Heuristic capability inference from import table."""
    all_funcs = set()
    for imp in imports:
        all_funcs.update(imp.get("functions", []))

    inferred = set()
    capability_map = {
        "CreateRemoteThread": "process injection",
        "WriteProcessMemory": "process injection",
        "VirtualAllocEx": "process injection",
        "NtUnmapViewOfSection": "process injection",
        "SetWindowsHookEx": "keylogging",
        "GetAsyncKeyState": "keylogging",
        "RegSetValueEx": "persistence",
        "OpenSCManager": "persistence",
        "CreateService": "persistence",
        "CryptEncrypt": "ransomware",
        "CryptGenKey": "ransomware",
        "IsDebuggerPresent": "anti-analysis",
        "CheckRemoteDebuggerPresent": "anti-analysis",
        "InternetOpenUrl": "network beaconing",
        "URLDownloadToFile": "network beaconing",
        "WinHttpOpen": "network beaconing",
        "GetClipboardData": "credential theft",
        "CredEnumerate": "credential theft",
    }
    for func, cap in capability_map.items():
        if func in all_funcs:
            inferred.add(cap)

    return list(inferred)


def run_capability_detection(
    file_path: Path,
    static_imports: Optional[list] = None,
) -> CapabilityResult:
    logger.info(f"[Capability] Detecting capabilities in: {file_path.name}")

    capabilities = []
    raw_capa = None

    # Try real CAPA first
    capa_output = _run_capa(file_path)
    if capa_output:
        raw_capa = capa_output
        capabilities = _parse_capa_output(capa_output)
        logger.info(f"[CAPA] Found {len(capabilities)} capabilities")
    else:
        # Fallback: heuristic from imports
        if static_imports:
            import_dicts = [i.model_dump() if hasattr(i, "model_dump") else i for i in static_imports]
            capabilities = _infer_capabilities_from_imports(import_dicts)
            logger.info(f"[Capability] Inferred {len(capabilities)} capabilities from imports")

    # Classify capabilities
    cap_lower = [c.lower() for c in capabilities]

    def has_cap(*keywords: str) -> bool:
        return any(k in c for k in keywords for c in cap_lower)

    return CapabilityResult(
        capabilities=capabilities,
        has_credential_theft=has_cap("credential"),
        has_keylogging=has_cap("keylog", "keystroke"),
        has_persistence=has_cap("persistence", "autorun"),
        has_ransomware=has_cap("ransom", "encrypt"),
        has_injection=has_cap("inject", "remote thread"),
        has_network_beaconing=has_cap("network", "beacon", "http"),
        has_discovery=has_cap("discovery", "enumerate"),
        raw_capa_output=raw_capa,
    )
