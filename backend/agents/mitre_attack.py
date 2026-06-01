"""
ViGiL — Agent 11: MITRE ATT&CK Mapping Agent
Maps detected behaviors, capabilities, and evasion techniques to ATT&CK techniques.
"""
from __future__ import annotations

from loguru import logger
from models import MITREResult, MITRETechnique


# Comprehensive behavior → ATT&CK technique mapping
TECHNIQUE_MAP: list[dict] = [
    # Discovery
    {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get detailed information about the operating system and hardware.",
        "triggers": ["discovery", "system info", "GetSystemInfo", "GetComputerName"],
    },
    {
        "technique_id": "T1057",
        "technique_name": "Process Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get information about running processes.",
        "triggers": ["process list", "CreateToolhelp32Snapshot", "enumerate process"],
    },
    # Execution
    {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands.",
        "triggers": ["powershell", "cmd.exe", "wscript", "cscript", "mshta"],
    },
    # Persistence
    {
        "technique_id": "T1547",
        "technique_name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "description": "Adversaries may configure system settings to execute a malicious payload at startup.",
        "triggers": ["persistence", "autorun", "registry run", "RegSetValueEx", "CreateService"],
    },
    {
        "technique_id": "T1543",
        "technique_name": "Create or Modify System Process",
        "tactic": "Persistence",
        "description": "Adversaries may create or modify Windows services to execute malicious payloads.",
        "triggers": ["CreateService", "OpenSCManager", "StartService"],
    },
    # Defense Evasion
    {
        "technique_id": "T1497",
        "technique_name": "Virtualization/Sandbox Evasion",
        "tactic": "Defense Evasion",
        "description": "Adversaries may employ various means to detect and avoid virtualization and analysis environments.",
        "triggers": ["anti_vm", "anti-vm", "VirtualBox", "VMware", "sandbox"],
    },
    {
        "technique_id": "T1027",
        "technique_name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze.",
        "triggers": ["api_obfuscation", "api hashing", "GetProcAddress", "string encryption", "packed"],
    },
    {
        "technique_id": "T1140",
        "technique_name": "Deobfuscate/Decode Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may use obfuscated files or information to hide artifacts.",
        "triggers": ["CryptDecrypt", "decrypt", "deobfuscate", "XOR", "Base64"],
    },
    {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "Defense Evasion",
        "description": "Adversaries may inject code into processes to evade process-based defenses.",
        "triggers": ["process injection", "inject", "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx"],
    },
    # Credential Access
    {
        "technique_id": "T1555",
        "technique_name": "Credentials from Password Stores",
        "tactic": "Credential Access",
        "description": "Adversaries may search for common password storage locations to obtain user credentials.",
        "triggers": ["credential theft", "CredEnumerate", "password", "credential"],
    },
    {
        "technique_id": "T1056",
        "technique_name": "Input Capture",
        "tactic": "Credential Access",
        "description": "Adversaries may use methods of capturing user input to obtain credentials.",
        "triggers": ["keylogging", "keylog", "GetAsyncKeyState", "SetWindowsHookEx"],
    },
    {
        "technique_id": "T1113",
        "technique_name": "Screen Capture",
        "tactic": "Collection",
        "description": "Adversaries may attempt to take screen captures of the desktop.",
        "triggers": ["screenshot", "BitBlt", "GetDesktopWindow", "screen capture"],
    },
    # Command and Control
    {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using OSI application layer protocols.",
        "triggers": ["network beaconing", "InternetConnect", "WinHttpConnect", "beacon", "C2", "http"],
    },
    {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversaries may transfer tools or other files from an external system.",
        "triggers": ["URLDownloadToFile", "download", "WinHttpSendRequest"],
    },
    # Impact
    {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems to interrupt availability.",
        "triggers": ["ransomware", "CryptEncrypt", "encrypt files", "ransom"],
    },
    {
        "technique_id": "T1490",
        "technique_name": "Inhibit System Recovery",
        "tactic": "Impact",
        "description": "Adversaries may delete or remove built-in operating system data and turn off recovery systems.",
        "triggers": ["shadow copy", "vssadmin", "bcdedit", "inhibit recovery"],
    },
    # Anti-Analysis
    {
        "technique_id": "T1622",
        "technique_name": "Debugger Evasion",
        "tactic": "Defense Evasion",
        "description": "Adversaries may employ various means to detect and avoid debuggers.",
        "triggers": ["anti_debug", "IsDebuggerPresent", "NtQueryInformationProcess", "anti-debug"],
    },
]


def run_mitre_attack_mapping(
    capabilities: list[str] = None,
    evasion: dict = None,
    emulation: dict = None,
    static_strings: list[str] = None,
    static_imports: list[str] = None,
) -> MITREResult:
    logger.info("[MITRE] Mapping findings to ATT&CK framework")

    # Build a combined feature set
    all_indicators = set()
    if capabilities:
        all_indicators.update(c.lower() for c in capabilities)
    if static_strings:
        all_indicators.update(s.lower() for s in static_strings[:500])
    if static_imports:
        all_indicators.update(i.lower() for i in static_imports)

    # Evasion flags
    if evasion:
        if evasion.get("anti_vm"):
            all_indicators.add("anti_vm")
        if evasion.get("anti_debug"):
            all_indicators.add("anti_debug")
        if evasion.get("api_obfuscation"):
            all_indicators.add("api_obfuscation")
        if evasion.get("anti_sandbox"):
            all_indicators.add("sandbox")

    mapped_techniques: list[MITRETechnique] = []
    tactics_covered: set[str] = set()

    for tech in TECHNIQUE_MAP:
        tech_triggers = [t.lower() for t in tech["triggers"]]
        confidence = 0.0
        matched_count = 0

        for trigger in tech_triggers:
            if any(trigger in indicator for indicator in all_indicators):
                matched_count += 1

        if matched_count > 0:
            confidence = min(matched_count / len(tech_triggers), 1.0)
            mapped_techniques.append(MITRETechnique(
                technique_id=tech["technique_id"],
                technique_name=tech["technique_name"],
                tactic=tech["tactic"],
                description=tech["description"],
                confidence=round(confidence, 2),
            ))
            tactics_covered.add(tech["tactic"])

    # Sort by confidence
    mapped_techniques.sort(key=lambda t: t.confidence, reverse=True)

    return MITREResult(
        techniques=mapped_techniques,
        tactics_covered=sorted(tactics_covered),
        technique_count=len(mapped_techniques),
    )
