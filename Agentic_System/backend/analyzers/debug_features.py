"""
ViGil — Debug & Anti-Analysis Detector
=======================================

Analyzes imports, assembly instructions, and strings to detect anti-debugging,
virtual machine (VM) detection, sandbox evasion, and timing-based check tricks,
computing an overall evasion probability score.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pefile

logger = logging.getLogger(__name__)

# Try to import Capstone
try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

# VM/Sandbox strings
VM_STRINGS = [
    b"vmware", b"vbox", b"virtualbox", b"qemu", b"xen", b"parallels",
    b"sandboxing", b"wireshark", b"procmon", b"processhacker", b"vboxguest",
    b"vboxservice", b"vmtoolsd",
]

# Anti-debug APIs
ANTI_DEBUG_APIS = {
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "OutputDebugStringA",
    "OutputDebugStringW", "NtSetInformationThread",
    "GetLastError", "SetUnhandledExceptionFilter",
}

# Sandbox evasion APIs (mostly sleep, time, user input interaction)
EVASION_APIS = {
    "Sleep", "SleepEx", "NtDelayExecution",
    "GetTickCount", "GetTickCount64", "QueryPerformanceCounter",
    "GetCursorPos", "GetLastInputInfo", "BlockInput",
}


class DebugFeatureAnalyzer:
    """Detects anti-debugging, anti-VM, and sandbox evasion features."""

    def analyze(self, pe_path: Path) -> dict[str, Any]:
        """Scan PE imports, instructions, and strings for evasion indicators.

        Returns
        -------
        dict
            Evasion flags, timing checks, VM detection indicators,
            and an overall evasion probability score.
        """
        result: dict[str, Any] = {
            "anti_debug_apis": [],
            "timing_checks": [],
            "vm_detection": [],
            "sandbox_evasion": [],
            "evasion_score": 0,
        }

        try:
            pe = pefile.PE(str(pe_path), fast_load=False)
        except Exception as exc:
            logger.error("Failed to parse PE in debug features analyzer %s: %s", pe_path, exc)
            result["error"] = str(exc)
            return result

        try:
            anti_debug = []
            timing = []
            vm = []
            evasion = []
            score = 0

            # 1. Check imports
            imported_apis = set()
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            name = imp.name.decode("utf-8", errors="replace")
                            imported_apis.add(name)

            for api in imported_apis:
                if api in ANTI_DEBUG_APIS:
                    anti_debug.append(api)
                    score += 15
                if api in EVASION_APIS:
                    # Distinguish timing/delay from UI input evasion
                    if "Cursor" in api or "Input" in api or "Block" in api:
                        evasion.append(api)
                        score += 20  # High signature weight
                    else:
                        timing.append(api)
                        score += 10

            # 2. String checking (anti-VM / sandbox strings)
            # Scan first 64KB of binary for efficiency
            try:
                with open(pe_path, "rb") as f:
                    file_slice = f.read(65536)
                
                for s in VM_STRINGS:
                    if s in file_slice.lower():
                        s_str = s.decode("ascii", errors="replace")
                        vm.append(f"string_marker:{s_str}")
                        score += 15
            except Exception as f_err:
                logger.warning("Failed to scan strings for VM checks: %s", f_err)

            # 3. Check instructions using Capstone
            if CAPSTONE_AVAILABLE:
                arch = pe.FILE_HEADER.Machine
                md = None
                if arch == 0x14C:  # x86
                    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                elif arch == 0x8664:  # x64
                    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

                if md:
                    for section in pe.sections:
                        if section.Characteristics & 0x20000000:  # Execute
                            code_data = section.get_data()
                            if not code_data:
                                continue
                            base_addr = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                            
                            # Disassemble and find instruction signatures
                            # E.g., rdtsc (timing check), cpuid (VM checking)
                            for inst in md.disasm(code_data, base_addr):
                                if inst.mnemonic == "rdtsc":
                                    if "rdtsc" not in timing:
                                        timing.append("rdtsc")
                                        score += 15
                                elif inst.mnemonic == "cpuid":
                                    if "cpuid" not in vm:
                                        vm.append("cpuid")
                                        score += 10

            result["anti_debug_apis"] = anti_debug
            result["timing_checks"] = timing
            result["vm_detection"] = vm
            result["sandbox_evasion"] = evasion
            result["evasion_score"] = min(score, 100)

        except Exception as exc:
            logger.exception("Error during debug feature analysis of %s", pe_path)
            result["error"] = str(exc)
        finally:
            pe.close()

        return result
