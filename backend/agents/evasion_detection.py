"""
ViGiL — Agent 6: Evasion Detection Agent
Detects anti-VM, anti-sandbox, anti-debug, anti-disassembly, and API obfuscation.
"""
from __future__ import annotations

from pathlib import Path
from models import EvasionResult
from loguru import logger


# ─── Anti-VM signatures ──────────────────────────────────────────────────────
ANTI_VM_STRINGS = [
    # VirtualBox
    "vboxhook", "vboxmouse", "vboxguest", "vboxsf", "vboxvideo",
    "VirtualBox", "VBOX", "innotek",
    # VMware
    "vmtoolsd", "vmwaretray", "vmwareuser", "vmware",
    "VMware", "VMWARE",
    # QEMU
    "qemu", "QEMU", "bochs", "BOCHS",
    # Hyper-V
    "VMMSVC", "vmbus", "vmbkmclr",
    # Generic
    "Sandbox", "SandBox", "SANDBOX", "WILBERT", "JOEBOX",
]

ANTI_VM_REGISTRY = [
    "HARDWARE\\ACPI\\DSDT\\VBOX__",
    "HARDWARE\\ACPI\\FADT\\VBOX__",
    "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
    "SOFTWARE\\VMware, Inc.\\VMware Tools",
    "SYSTEM\\ControlSet001\\Services\\VBoxGuest",
]

ANTI_VM_IMPORTS = [
    "cpuid", "rdtsc",  # timing/CPU ID checks
]

ANTI_VM_MAC_PREFIXES = [
    "08:00:27",  # VirtualBox
    "00:0C:29",  # VMware
    "00:50:56",  # VMware
    "00:1C:42",  # Parallels
]

# ─── Anti-Sandbox ────────────────────────────────────────────────────────────
ANTI_SANDBOX_STRINGS = [
    "GetTickCount", "timeGetTime", "QueryPerformanceCounter",
    "sleep", "Sleep", "WaitForSingleObject",
    "GetCursorPos", "GetLastInputInfo",
    "GetForegroundWindow",
    "SbieDll", "sbiedll",  # Sandboxie
    "api_log", "dir_watch",  # Cuckoo
    "dbgview",
]

SLEEP_THRESHOLD = 5000  # ms

# ─── Anti-Debug ──────────────────────────────────────────────────────────────
ANTI_DEBUG_IMPORTS = [
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "OutputDebugString",
    "FindWindow",
    "GetWindowText",
    "NtSetInformationThread",
    "CloseHandle",  # can be used with invalid handle for debug detection
    "ZwSetInformationThread",
    "RtlAdjustPrivilege",
]

ANTI_DEBUG_STRINGS = [
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "ProcessDebugPort",
    "ScyllaHide", "x64dbg", "OllyDbg", "WinDbg",
    "IDA", "Ghidra",
]

# ─── Anti-Disassembly ────────────────────────────────────────────────────────
ANTI_DISASM_BYTE_PATTERNS = [
    b"\xEB\xFF\xC0\x48",   # jump over invalid byte
    b"\xE8\x00\x00\x00\x00",  # fake call
]

# ─── API Obfuscation ─────────────────────────────────────────────────────────
API_OBFUSCATION_STRINGS = [
    "LoadLibraryA", "GetProcAddress",
    "LdrGetProcedureAddress",
    "NtOpenFile", "LdrLoadDll",
    "GetModuleHandleA",
]


def _scan_strings_for_patterns(strings: list[str], patterns: list[str]) -> list[str]:
    """Find which patterns appear in the string list."""
    found = []
    strings_joined = "\n".join(strings).lower()
    for p in patterns:
        if p.lower() in strings_joined:
            found.append(p)
    return found


def _check_raw_bytes(raw: bytes, patterns: list[bytes]) -> list[str]:
    found = []
    for p in patterns:
        if p in raw:
            found.append(p.hex())
    return found


def run_evasion_detection(
    file_path: Path,
    static_strings: list[str] = None,
    static_imports: list = None,
) -> EvasionResult:
    logger.info(f"[Evasion] Detecting evasion techniques in: {file_path.name}")

    strings = static_strings or []
    all_import_funcs: list[str] = []
    if static_imports:
        for imp in static_imports:
            if hasattr(imp, "functions"):
                all_import_funcs.extend(imp.functions)
            elif isinstance(imp, dict):
                all_import_funcs.extend(imp.get("functions", []))

    combined = strings + all_import_funcs

    # Anti-VM
    anti_vm_found = _scan_strings_for_patterns(combined, ANTI_VM_STRINGS)
    anti_vm_registry = _scan_strings_for_patterns(combined, ANTI_VM_REGISTRY)
    anti_vm_techniques = anti_vm_found + anti_vm_registry

    # Anti-Sandbox
    anti_sandbox_found = _scan_strings_for_patterns(combined, ANTI_SANDBOX_STRINGS)

    # Anti-Debug
    anti_debug_found = _scan_strings_for_patterns(
        combined, ANTI_DEBUG_IMPORTS + ANTI_DEBUG_STRINGS
    )

    # Anti-Disassembly: check raw bytes
    with open(file_path, "rb") as f:
        raw = f.read(1024 * 1024)  # first 1 MB
    anti_disasm_bytes = _check_raw_bytes(raw, ANTI_DISASM_BYTE_PATTERNS)
    anti_disasm_techniques = anti_disasm_bytes

    # API Obfuscation
    api_obfusc_found = _scan_strings_for_patterns(combined, API_OBFUSCATION_STRINGS)
    # Check if GetProcAddress + LoadLibrary present (indirect API resolution)
    api_hashing = (
        "GetProcAddress" in all_import_funcs and "LoadLibraryA" in all_import_funcs
    )
    api_obfusc_techniques = api_obfusc_found
    if api_hashing:
        api_obfusc_techniques.append("indirect API resolution via GetProcAddress")

    # Compute evasion score (0–100)
    score = 0
    if anti_vm_techniques:
        score += 25
    if anti_sandbox_found:
        score += 20
    if anti_debug_found:
        score += 25
    if anti_disasm_techniques:
        score += 15
    if api_obfusc_techniques:
        score += 15

    score = min(score, 100)

    return EvasionResult(
        anti_vm=bool(anti_vm_techniques),
        anti_vm_techniques=list(set(anti_vm_techniques))[:10],
        anti_sandbox=bool(anti_sandbox_found),
        anti_sandbox_techniques=list(set(anti_sandbox_found))[:10],
        anti_debug=bool(anti_debug_found),
        anti_debug_techniques=list(set(anti_debug_found))[:10],
        anti_disassembly=bool(anti_disasm_techniques),
        anti_disassembly_techniques=anti_disasm_techniques[:5],
        api_obfuscation=bool(api_obfusc_techniques),
        api_obfuscation_techniques=list(set(api_obfusc_techniques))[:10],
        evasion_score=score,
    )
