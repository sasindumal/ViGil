"""
ViGiL — Agent 14: Automatic YARA Generation Agent
Generates YARA hunting rules from unique strings, APIs, and capabilities.
"""
from __future__ import annotations

import re
from pathlib import Path
from loguru import logger

from models import YARAResult, YARARule


def _sanitize_yara_string(s: str) -> str:
    """Escape special characters for YARA string definitions."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _make_generic_rule(
    sha256: str,
    suspicious_strings: list[str],
    suspicious_apis: list[str],
) -> YARARule:
    """Generic suspicious indicator rule."""
    strings_block = ""
    if suspicious_strings:
        for i, s in enumerate(suspicious_strings[:5]):
            clean = _sanitize_yara_string(s)
            strings_block += f'        $str_{i} = "{clean}" nocase\n'

    if suspicious_apis:
        for i, api in enumerate(suspicious_apis[:5]):
            strings_block += f'        $api_{i} = "{api}" ascii\n'

    conditions = []
    if suspicious_strings:
        conditions.append("2 of ($str_*)")
    if suspicious_apis:
        conditions.append("2 of ($api_*)")

    condition = " and ".join(conditions) if conditions else "all of them"

    rule_content = f"""rule ViGiL_Suspicious_Generic
{{
    meta:
        description = "Suspicious binary with multiple malware indicators"
        generated_by = "ViGiL Automated YARA Generator"
        sample_sha256 = "{sha256}"
        confidence = "medium"

    strings:
{strings_block or "        $placeholder = {{ 4D 5A }}  // MZ header"}

    condition:
        uint16(0) == 0x5A4D and ({condition})
}}"""

    return YARARule(
        rule_name="ViGiL_Suspicious_Generic",
        rule_type="generic",
        description="Generic detection rule based on suspicious indicators",
        rule_content=rule_content,
    )


def _make_family_rule(
    family: str,
    sha256: str,
    capabilities: list[str],
    techniques: list[str],
) -> YARARule:
    """Family-specific detection rule."""
    family_clean = re.sub(r"[^a-zA-Z0-9_]", "_", family)

    strings_block = f'        $family = "{family}" nocase wide\n'

    cap_map = {
        "process injection": ["CreateRemoteThread", "WriteProcessMemory"],
        "credential theft": ["CredEnumerate", "CryptUnprotectData"],
        "keylogging": ["SetWindowsHookEx", "GetAsyncKeyState"],
        "persistence": ["RegSetValueEx", "CreateService"],
        "network beaconing": ["InternetOpenUrl", "WinHttpConnect"],
        "ransomware": ["CryptEncrypt", "CryptGenKey"],
    }

    api_strings = []
    for cap in capabilities:
        apis = cap_map.get(cap.lower(), [])
        api_strings.extend(apis)

    for i, api in enumerate(list(set(api_strings))[:6]):
        strings_block += f'        $api_{i} = "{api}" ascii\n'

    rule_content = f"""rule ViGiL_{family_clean}_Family
{{
    meta:
        description = "Detection rule for {family} malware family"
        generated_by = "ViGiL Automated YARA Generator"
        sample_sha256 = "{sha256}"
        mitre_techniques = "{', '.join(techniques[:5])}"
        confidence = "high"

    strings:
{strings_block}
    condition:
        uint16(0) == 0x5A4D and
        $family and
        2 of ($api_*)
}}"""

    return YARARule(
        rule_name=f"ViGiL_{family_clean}_Family",
        rule_type="family",
        description=f"Detection rule for {family} malware family",
        rule_content=rule_content,
    )


def _make_sample_rule(
    sha256: str,
    md5: str,
    unique_strings: list[str],
) -> YARARule:
    """Exact sample-matching rule using unique strings."""
    strings_block = f'        $sha256 = "{sha256}" ascii\n'
    for i, s in enumerate(unique_strings[:8]):
        clean = _sanitize_yara_string(s)
        if len(clean) >= 8:
            strings_block += f'        $unique_{i} = "{clean}" ascii wide\n'

    rule_content = f"""rule ViGiL_Sample_{sha256[:12]}
{{
    meta:
        description = "Exact sample match for SHA256: {sha256}"
        generated_by = "ViGiL Automated YARA Generator"
        sha256 = "{sha256}"
        md5 = "{md5}"
        confidence = "very_high"

    strings:
{strings_block}
    condition:
        uint16(0) == 0x5A4D and
        3 of ($unique_*)
}}"""

    return YARARule(
        rule_name=f"ViGiL_Sample_{sha256[:12]}",
        rule_type="sample",
        description=f"Exact sample detection rule for SHA256: {sha256}",
        rule_content=rule_content,
    )


def run_yara_generation(
    sha256: str,
    md5: str = "",
    suspicious_strings: list[str] = None,
    suspicious_apis: list[str] = None,
    capabilities: list[str] = None,
    techniques: list[str] = None,
    family: str = None,
    output_dir: Path = None,
) -> YARAResult:
    logger.info("[YARA] Generating detection rules")

    suspicious_strings = suspicious_strings or []
    suspicious_apis = suspicious_apis or []
    capabilities = capabilities or []
    techniques = techniques or []

    rules: list[YARARule] = []

    # Generate generic rule
    generic_rule = _make_generic_rule(sha256, suspicious_strings, suspicious_apis)
    rules.append(generic_rule)

    # Generate family rule if family identified
    if family and family.lower() not in ("unknown", "novel / unknown family"):
        family_rule = _make_family_rule(family, sha256, capabilities, techniques)
        rules.append(family_rule)

    # Generate sample rule
    unique_strings = [s for s in suspicious_strings if len(s) >= 8][:10]
    sample_rule = _make_sample_rule(sha256, md5, unique_strings)
    rules.append(sample_rule)

    # Write combined YARA file
    combined_path = None
    if output_dir:
        combined_path = output_dir / "generated.yara"
        with open(combined_path, "w") as f:
            f.write("// ViGiL Auto-Generated YARA Rules\n")
            f.write(f"// Sample: {sha256}\n\n")
            for rule in rules:
                f.write(rule.rule_content + "\n\n")

    return YARAResult(
        rules=rules,
        combined_yara_path=str(combined_path) if combined_path else None,
    )
