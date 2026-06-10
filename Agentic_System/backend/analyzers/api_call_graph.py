"""
ViGil — API Call Graph & Behavior Chains
==========================================

Analyzes code sections for calls to imported APIs, maps them to sequence graphs,
and identifies behavior chains indicative of process injection, network C2,
registry persistence, or ransomware-style crypto operations.
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


class APICallGraphAnalyzer:
    """Extracts API call graph patterns and detects malicious behavior chains."""

    def analyze(self, pe_path: Path) -> dict[str, Any]:
        """Build API call graph and recognize behavior signatures.

        Returns
        -------
        dict
            Call graph representation, identified behavior chains, and predicted behaviors.
        """
        result: dict[str, Any] = {
            "call_graph": {},
            "behavior_chains": [],
            "predicted_behaviors": [],
        }

        try:
            pe = pefile.PE(str(pe_path), fast_load=False)
        except Exception as exc:
            logger.error("Failed to parse PE in API call graph analyzer %s: %s", pe_path, exc)
            result["error"] = str(exc)
            return result

        try:
            # 1. Gather all imported APIs and their addresses
            iat_map = {}
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name and imp.address:
                            # Map IAT entry address to API name
                            iat_map[imp.address] = imp.name.decode("utf-8", errors="replace")

            # 2. Extract call graph using Capstone if available
            call_graph = {}
            if CAPSTONE_AVAILABLE and iat_map:
                arch = pe.FILE_HEADER.Machine
                if arch == 0x14C:  # x86
                    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                elif arch == 0x8664:  # x64
                    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                else:
                    md = None

                if md:
                    md.detail = True
                    # Scan executable sections for calls to IAT entries
                    for section in pe.sections:
                        if section.Characteristics & 0x20000000:  # Execute
                            code_data = section.get_data()
                            if not code_data:
                                continue
                            base_addr = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                            
                            # Simple tracking of current function (offset)
                            current_func = "unknown_offset"
                            
                            for inst in md.disasm(code_data, base_addr):
                                mnemonic = inst.mnemonic
                                op_str = inst.op_str
                                address = inst.address

                                # Heuristic function boundary
                                if mnemonic == "push" and op_str == "ebp":
                                    current_func = f"func_{hex(address)}"
                                    call_graph[current_func] = []
                                elif mnemonic == "sub" and "rsp" in op_str:
                                    current_func = f"func_{hex(address)}"
                                    call_graph[current_func] = []

                                if mnemonic == "call":
                                    # Check if the call operand is an address or reference to the IAT
                                    # E.g. call dword ptr [0x401000]
                                    called_api = None
                                    # Simple parsing of operand string
                                    for addr in iat_map:
                                        if hex(addr) in op_str or f"[{hex(addr)}]" in op_str:
                                            called_api = iat_map[addr]
                                            break
                                    
                                    if called_api:
                                        if current_func not in call_graph:
                                            call_graph[current_func] = []
                                        call_graph[current_func].append(called_api)

            # Cap the call graph representation to keep JSON compact
            result["call_graph"] = {k: v for k, v in call_graph.items() if v}

            # 3. Analyze Behavior Chains (Flat scan of IAT imports as a fallback/augment)
            # Create a flat list of imported APIs
            flat_apis = set(iat_map.values())

            # Define known behavior chains and signatures
            behavior_signatures = [
                {
                    "name": "Process Injection",
                    "chain": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
                    "description": "Allocates memory, writes code, and executes thread in a remote process.",
                    "severity": "critical",
                },
                {
                    "name": "Process Hollowing",
                    "chain": ["CreateProcess", "NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory", "ResumeThread"],
                    "description": "Creates a suspended process, unmaps its memory, replaces with malicious code, and resumes execution.",
                    "severity": "critical",
                },
                {
                    "name": "C2 Communication",
                    "chain": ["InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest"],
                    "description": "Establishes a connection to a remote web server for command and control.",
                    "severity": "high",
                },
                {
                    "name": "Credential Dumping",
                    "chain": ["OpenProcess", "MiniDumpWriteDump"],
                    "description": "Accesses LSASS process memory to dump user credentials.",
                    "severity": "high",
                },
                {
                    "name": "Registry Persistence",
                    "chain": ["RegCreateKeyEx", "RegSetValueEx"],
                    "description": "Creates or modifies a registry key to survive system reboots.",
                    "severity": "medium",
                },
                {
                    "name": "Ransomware Operations",
                    "chain": ["FindFirstFile", "FindNextFile", "CryptEncrypt"],
                    "description": "Enumerates directory files and encrypts them using cryptographic APIs.",
                    "severity": "critical",
                }
            ]

            predicted_behaviors = []
            behavior_chains = []

            for sig in behavior_signatures:
                # Check how many APIs in the signature chain are present in the import table
                # We do substring matching to catch A/W variants (e.g. CreateProcessA or CreateProcessW)
                matched_apis = []
                for step in sig["chain"]:
                    for api in flat_apis:
                        if step in api:
                            matched_apis.append(api)
                            break
                
                # If a significant part of the chain is imported, report it
                match_ratio = len(matched_apis) / len(sig["chain"])
                if match_ratio >= 0.6:  # If at least 60% of the chain exists
                    predicted_behaviors.append({
                        "name": sig["name"],
                        "severity": sig["severity"],
                        "confidence": int(match_ratio * 100),
                        "description": sig["description"],
                    })
                    behavior_chains.append({
                        "signature_name": sig["name"],
                        "matched_apis": matched_apis,
                        "missing_apis": [s for s in sig["chain"] if not any(s in a for a in matched_apis)],
                    })

            result["predicted_behaviors"] = predicted_behaviors
            result["behavior_chains"] = behavior_chains

        except Exception as exc:
            logger.exception("Error during API call graph analysis of %s", pe_path)
            result["error"] = str(exc)
        finally:
            pe.close()

        return result
