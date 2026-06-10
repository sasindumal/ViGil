"""
ViGil — Signature and YARA-style Matcher
========================================

Implements pattern matching using YARA rules (if available) and falls back
to manual regex/byte-scanning for shellcode patterns, NOP sleds, PEB walking,
API hashing, and common malware family signatures.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Try to import YARA
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

# Built-in fallback byte signatures (regex or simple scan)
# Format: { "Family/Type Name": b"hex pattern" or "string pattern" }
BYTE_SIGNATURES = {
    "Metasploit Shellcode / PEB Walking": [
        b"\x64\xa1\x30\x00\x00\x00",      # mov eax, fs:[0x30] (PEB offset x86)
        b"\x65\x48\x8b\x52\x60",          # mov rdx, gs:[0x60] (PEB offset x64)
    ],
    "NOP Sled": [
        b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90", # 16 NOPs
    ],
    "Cobalt Strike / Metasploit User-Agent": [
        b"InternetConnectA",
        b"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
    ],
    "Common RAT Command Pattern": [
        b"keepalive",
        b"cmd.exe /c",
        b"ping 127.0.0.1 -n",
    ],
}

# Embedded YARA Rules for compile
YARA_RULES = """
rule shellcode_peb {
    meta:
        description = "Detects assembly patterns used to walk the Process Environment Block (PEB)"
    strings:
        $x86_peb = { 64 A1 30 00 00 00 }
        $x64_peb = { 65 48 8B 52 60 }
    condition:
        any of them
}

rule nop_sled {
    meta:
        description = "Detects long NOP sequences often used in buffer overflows or shellcode"
    strings:
        $nop = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    condition:
        $nop
}

rule cobalt_strike_beacon {
    meta:
        description = "Detects common strings used in Cobalt Strike beacons"
    strings:
        $s1 = "%%email%%"
        $s2 = "%s (admin)"
        $s3 = "c2_server"
        $ua = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)"
    condition:
        2 of them or $ua
}

rule generic_rat_indicators {
    meta:
        description = "Detects generic strings associated with Remote Access Trojans"
    strings:
        $r1 = "keylogger" nocase
        $r2 = "screenshot" nocase
        $r3 = "port_scan" nocase
        $r4 = "download_execute" nocase
        $r5 = "mutex_created" nocase
    condition:
        2 of them
}
"""


class SignatureAnalyzer:
    """Matches files against YARA rules and byte patterns."""

    def analyze(self, pe_path: Path) -> dict[str, Any]:
        """Perform signature matching on a file.

        Returns
        -------
        dict
            Matched signatures, matched families, and shellcode indicators.
        """
        result: dict[str, Any] = {
            "matched_signatures": [],
            "matched_families": [],
            "shellcode_indicators": [],
            "yara_available": YARA_AVAILABLE,
        }

        try:
            with open(pe_path, "rb") as f:
                data = f.read()
        except Exception as exc:
            logger.error("Failed to read file for signature scanning %s: %s", pe_path, exc)
            result["error"] = str(exc)
            return result

        try:
            matched_sigs = []
            matched_families = []
            shellcode_ind = []

            # 1. YARA Scanning
            if YARA_AVAILABLE:
                try:
                    rules = yara.compile(source=YARA_RULES)
                    matches = rules.match(data=data)
                    for m in matches:
                        matched_sigs.append({
                            "rule": m.rule,
                            "tags": m.tags,
                            "meta": m.meta,
                        })
                        if "rat" in m.rule or "cobalt" in m.rule:
                            matched_families.append(m.rule)
                        if "peb" in m.rule or "nop" in m.rule:
                            shellcode_ind.append(m.rule)
                except Exception as y_err:
                    logger.warning("YARA match failed, falling back: %s", y_err)

            # 2. Fallback Byte/String Scanning
            # Always run fallback to ensure defense-in-depth and cover situations where YARA compilation fails
            for family, patterns in BYTE_SIGNATURES.items():
                for pat in patterns:
                    if pat in data:
                        match_info = {
                            "name": family,
                            "pattern_matched": pat.hex() if len(pat) > 5 and b"\x00" in pat else pat.decode("ascii", errors="replace"),
                            "method": "byte_scan"
                        }
                        if match_info["name"] not in [m.get("name") for m in matched_sigs]:
                            matched_sigs.append(match_info)

                        if "Shellcode" in family or "NOP" in family:
                            if family not in shellcode_ind:
                                shellcode_ind.append(family)
                        else:
                            if family not in matched_families:
                                matched_families.append(family)

            result["matched_signatures"] = matched_sigs
            result["matched_families"] = matched_families
            result["shellcode_indicators"] = shellcode_ind

        except Exception as exc:
            logger.exception("Error during signature analysis of %s", pe_path)
            result["error"] = str(exc)

        return result
