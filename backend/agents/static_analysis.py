"""
ViGiL — Agent 2: Static Analysis Agent
Deep static PE analysis: sections, imports, strings, suspicious indicators.
"""
from __future__ import annotations

import re
import subprocess
import math
from pathlib import Path
from typing import Optional

from loguru import logger

from models import StaticAnalysisResult, PESection, Import


# ─── Suspicious patterns ──────────────────────────────────────────────────────
URL_RE = re.compile(
    r"https?://[^\s\"'<>\x00-\x1f]{5,200}",
    re.IGNORECASE,
)
IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|xyz|ru|cn|top|info|biz|cc|tk|pw)\b",
    re.IGNORECASE,
)
MUTEX_RE = re.compile(r"(?:Global\\|Local\\)?[A-Za-z0-9_\-]{8,64}Mutex", re.IGNORECASE)
REGISTRY_RE = re.compile(
    r"(?:HKEY_|HKLM|HKCU|SOFTWARE\\|SYSTEM\\CurrentControlSet)[^\x00\n]{5,120}"
)
POWERSHELL_RE = re.compile(
    r"(?:powershell|cmd\.exe|wscript|cscript|mshta|regsvr32)[^\x00\n]{0,80}",
    re.IGNORECASE,
)

SUSPICIOUS_IMPORTS = {
    "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "NtUnmapViewOfSection",
    "SetWindowsHookEx", "GetAsyncKeyState", "GetClipboardData", "CryptEncrypt",
    "InternetOpenUrl", "URLDownloadToFile", "ShellExecute", "WinExec",
    "IsDebuggerPresent", "NtQueryInformationProcess", "CheckRemoteDebuggerPresent",
    "OpenSCManager", "CreateService", "RegSetValueEx",
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def _extract_strings_subprocess(file_path: Path) -> list[str]:
    """Use system 'strings' binary or FLOSS if available."""
    results: list[str] = []
    # Try FLOSS first
    for cmd in [["floss", str(file_path)], ["strings", "-n", "6", str(file_path)]]:
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            if out.returncode == 0:
                results = out.stdout.splitlines()
                logger.debug(f"[StaticAnalysis] Extracted {len(results)} strings via {cmd[0]}")
                return results
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    # Pure Python fallback — extract printable ASCII sequences ≥6 chars
    with open(file_path, "rb") as f:
        raw = f.read()
    current = []
    for byte in raw:
        if 0x20 <= byte <= 0x7E:
            current.append(chr(byte))
        else:
            if len(current) >= 6:
                results.append("".join(current))
            current = []
    return results


def run_static_analysis(file_path: Path) -> StaticAnalysisResult:
    logger.info(f"[StaticAnalysis] Running on: {file_path.name}")

    sections: list[PESection] = []
    imports: list[Import] = []
    exports: list[str] = []
    high_entropy: list[str] = []
    has_overlay = False
    has_tls = False
    has_cert = False
    avg_entropy = 0.0

    try:
        import pefile

        pe = pefile.PE(str(file_path))

        # Sections
        for s in pe.sections:
            name = s.Name.decode("utf-8", errors="replace").rstrip("\x00")
            data = s.get_data()
            ent = _entropy(data)
            char = hex(s.Characteristics)
            sec = PESection(
                name=name,
                virtual_size=s.Misc_VirtualSize,
                raw_size=s.SizeOfRawData,
                entropy=round(ent, 2),
                characteristics=char,
            )
            sections.append(sec)
            if ent > 7.0:
                high_entropy.append(name)

        avg_entropy = sum(s.entropy for s in sections) / max(len(sections), 1)

        # Imports
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="replace")
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        funcs.append(imp.name.decode("utf-8", errors="replace"))
                imports.append(Import(dll=dll, functions=funcs))

        # Exports
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(exp.name.decode("utf-8", errors="replace"))

        # TLS Callbacks
        has_tls = hasattr(pe, "DIRECTORY_ENTRY_TLS")

        # Overlay
        overlay_offset = pe.get_overlay_data_start_offset()
        has_overlay = overlay_offset is not None

        # Certificate
        has_cert = hasattr(pe, "DIRECTORY_ENTRY_SECURITY")

        pe.close()

    except ImportError:
        logger.warning("[StaticAnalysis] pefile not installed — skipping PE parsing")
    except Exception as e:
        logger.warning(f"[StaticAnalysis] PE parsing error: {e}")

    # String extraction
    raw_strings = _extract_strings_subprocess(file_path)

    # Classify strings
    urls = list(set(URL_RE.findall("\n".join(raw_strings))))[:50]
    ips = list(set(IP_RE.findall("\n".join(raw_strings))))[:50]
    domains = list(set(DOMAIN_RE.findall("\n".join(raw_strings))))[:50]
    mutexes = list(set(MUTEX_RE.findall("\n".join(raw_strings))))[:20]
    registry_keys = list(set(REGISTRY_RE.findall("\n".join(raw_strings))))[:30]
    commands = list(set(POWERSHELL_RE.findall("\n".join(raw_strings))))[:20]

    # Suspicious strings (imports + raw)
    all_import_funcs = {fn for imp in imports for fn in imp.functions}
    suspicious_api = [fn for fn in all_import_funcs if fn in SUSPICIOUS_IMPORTS]

    return StaticAnalysisResult(
        sections=sections,
        imports=imports,
        exports=exports,
        suspicious_strings=suspicious_api,
        urls=urls,
        ips=ips,
        domains=domains,
        mutexes=mutexes,
        registry_keys=registry_keys,
        commands=commands,
        has_overlay=has_overlay,
        has_tls_callbacks=has_tls,
        has_certificate=has_cert,
        average_entropy=round(avg_entropy, 2),
        high_entropy_sections=high_entropy,
    )
