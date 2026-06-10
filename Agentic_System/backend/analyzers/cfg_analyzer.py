"""
ViGil — Control Flow Graph (CFG) Approximation
================================================

Disassembles executable sections of a PE file using the Capstone engine
to approximate control flow structures, count basic blocks, indirect branches,
approximate cyclomatic complexity, and detect control flow obfuscation signatures.
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


class CFGAnalyzer:
    """Approximates the control flow graph structure and flags obfuscation."""

    def analyze(self, pe_path: Path) -> dict[str, Any]:
        """Disassemble and analyze control flow characteristics.

        Returns
        -------
        dict
            Function count, basic block count, indirect call/jump counts,
            cyclomatic complexity approximation, and obfuscation indicators.
        """
        result: dict[str, Any] = {
            "function_count": 0,
            "basic_block_count": 0,
            "indirect_calls": 0,
            "indirect_jumps": 0,
            "complexity_score": 0,
            "obfuscation_indicators": [],
            "capstone_available": CAPSTONE_AVAILABLE,
        }

        if not CAPSTONE_AVAILABLE:
            result["status"] = "skipped (capstone not installed)"
            return result

        try:
            pe = pefile.PE(str(pe_path), fast_load=False)
        except Exception as exc:
            logger.error("Failed to parse PE in CFG analyzer %s: %s", pe_path, exc)
            result["error"] = str(exc)
            return result

        try:
            # Determine architecture (x86 vs x64)
            arch = pe.FILE_HEADER.Machine
            if arch == 0x14C:  # i386
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            elif arch == 0x8664:  # AMD64
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            else:
                result["status"] = f"skipped (unsupported architecture: {hex(arch)})"
                return result

            # Enable detail mode for instruction properties
            md.detail = True

            function_count = 0
            basic_block_count = 0
            indirect_calls = 0
            indirect_jumps = 0
            complexity_score = 0
            obfuscation_indicators = []

            # Analyze only executable sections
            for section in pe.sections:
                if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    code_data = section.get_data()
                    if not code_data:
                        continue

                    # Disassemble the code bytes
                    base_addr = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                    instructions = list(md.disasm(code_data, base_addr))

                    if not instructions:
                        continue

                    # Heuristic function & block detection
                    # Functions typically begin with standard prologues
                    # Basic blocks are divided by branches, jumps, returns, and calls
                    for inst in instructions:
                        mnemonic = inst.mnemonic
                        op_str = inst.op_str

                        # Function boundary detection (prologues)
                        # push ebp; mov ebp, esp  OR  sub rsp, ...
                        if mnemonic == "push" and op_str == "ebp":
                            function_count += 1
                        elif mnemonic == "sub" and "rsp" in op_str:
                            function_count += 1
                        
                        # Basic block boundary detection
                        # Jumps, branches, calls, returns end a basic block
                        if mnemonic.startswith("j") or mnemonic in ["call", "ret"]:
                            basic_block_count += 1
                            complexity_score += 1  # Standard cyclomatic complexity approximation

                        # Indirect calls and jumps (e.g. call eax, jmp [ebp-4], etc.)
                        # These are often used in obfuscation, packers, or shellcode
                        if mnemonic == "call":
                            # Check if the operand is register or memory location rather than immediate value
                            if not op_str.startswith("0x"):
                                indirect_calls += 1
                        elif mnemonic == "jmp":
                            if not op_str.startswith("0x"):
                                indirect_jumps += 1

            # Obfuscation heuristics
            if indirect_jumps > 25:
                obfuscation_indicators.append({
                    "type": "high_indirect_jumps",
                    "severity": "medium",
                    "detail": f"High number of indirect jumps ({indirect_jumps}) — indicator of control flow flattening or VM protection"
                })
            
            if basic_block_count > 50 and function_count == 0:
                # Disassembled blocks but found no standard prologues
                obfuscation_indicators.append({
                    "type": "stripped_prologues",
                    "severity": "medium",
                    "detail": "Large code block with no standard function prologues detected — likely obfuscated, hand-crafted assembly or shellcode"
                })

            result["function_count"] = max(function_count, 1)
            result["basic_block_count"] = basic_block_count
            result["indirect_calls"] = indirect_calls
            result["indirect_jumps"] = indirect_jumps
            result["complexity_score"] = complexity_score
            result["obfuscation_indicators"] = obfuscation_indicators

        except Exception as exc:
            logger.exception("Error during CFG analysis of %s", pe_path)
            result["error"] = str(exc)
        finally:
            pe.close()

        return result
