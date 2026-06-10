"""
ViGil — Packer and Compiler Fingerprinter
===========================================

Identifies compiler frameworks (MSVC, MinGW, Delphi, Go, Rust) and packers
(UPX, Themida, VMProtect, MPRESS) by analyzing section properties, Rich headers,
linker timestamps, and specific string markers.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pefile

logger = logging.getLogger(__name__)


class PackerDetector:
    """Fingerprints binary compilers, linkers, and packers."""

    def analyze(self, pe_path: Path) -> dict[str, Any]:
        """Fingerprint compiler, linker, and packer details.

        Returns
        -------
        dict
            Compiler, packer, linker info, Rich header structure, and anomalies.
        """
        result: dict[str, Any] = {
            "compiler": "unknown",
            "packer": "none",
            "linker_info": {},
            "rich_header": {},
            "anomalies": [],
        }

        try:
            pe = pefile.PE(str(pe_path), fast_load=False)
        except Exception as exc:
            logger.error("Failed to parse PE in packer detector %s: %s", pe_path, exc)
            result["error"] = str(exc)
            return result

        try:
            # 1. Detect compiler and packer based on section names
            sections = []
            for sec in pe.sections:
                try:
                    name = sec.Name.rstrip(b"\x00").decode("utf-8", errors="replace").lower()
                except Exception:
                    name = sec.Name.hex()
                sections.append(name)

            compiler = "unknown"
            packer = "none"
            anomalies = []

            # Compiler rules
            # Go
            if ".gopclntab" in sections or "go.buildid" in sections or any(s.startswith(".go") for s in sections):
                compiler = "Go"
            # Rust
            # Rust doesn't have unique section names, but we can scan string/data references. Let's check imports or data later
            # Delphi
            elif "code" in sections and "data" in sections and "bss" in sections:
                compiler = "Delphi"
            # MinGW
            elif ".idata$" in sections or any(s.startswith(".mingw") for s in sections):
                compiler = "MinGW (GCC)"
            # MSVC - typically has .text, .rdata, .data, .reloc and a RICH header
            elif hasattr(pe, "RICH_HEADER"):
                compiler = "Microsoft Visual C++ (MSVC)"
            elif ".text" in sections and ".rdata" in sections and ".data" in sections:
                compiler = "Standard C/C++ (MSVC or compatible)"

            # Packer rules
            if any("upx" in s for s in sections):
                packer = "UPX"
            elif any("vmp" in s for s in sections):
                packer = "VMProtect"
            elif any("themida" in s or "winlicense" in s for s in sections):
                packer = "Themida"
            elif any("aspack" in s for s in sections):
                packer = "ASPack"
            elif any("mpress" in s for s in sections):
                packer = "MPRESS"
            elif any(".pec" in s for s in sections):
                packer = "PECompact"

            # 2. Rich Header Analysis
            rich_info = {}
            if hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER:
                rich = pe.RICH_HEADER
                rich_info["key"] = hex(rich.key)
                
                # Each entry contains tool ID, build number, and use count
                entries = []
                for entry in rich.values:
                    # Tool ID is high 16 bits, build is low 16 bits
                    tool_id = entry >> 16
                    build = entry & 0xffff
                    # Count is the value at index + 1
                    # pefile represents values as a flat list [val1, count1, val2, count2, ...]
                    entries.append({
                        "tool_id": tool_id,
                        "build": build,
                    })
                rich_info["entries"] = entries
                rich_info["present"] = True
            else:
                rich_info["present"] = False

            # Rust fallback check: check if it imports rust panics or contains rust strings
            if compiler == "unknown":
                try:
                    # Read the first 4096 bytes or section data to look for Rust indicators
                    # (Quick check in string imports)
                    data_slice = pe.get_data(0, 8192)
                    if b"rust_panic" in data_slice or b"std::panicking" in data_slice:
                        compiler = "Rust"
                except Exception:
                    pass

            # 3. Linker info & anomalies
            linker_major = pe.OPTIONAL_HEADER.MajorLinkerVersion
            linker_minor = pe.OPTIONAL_HEADER.MinorLinkerVersion
            linker_info = {
                "version": f"{linker_major}.{linker_minor}",
                "timestamp": pe.FILE_HEADER.TimeDateStamp,
            }

            # Anomalies in linker/packer
            # Example: Packer detected but no signature
            if packer != "none" and packer != "UPX" and not rich_info["present"]:
                anomalies.append({
                    "type": "packed_binary",
                    "severity": "medium",
                    "detail": f"File is packed using {packer}"
                })
            
            # Rich header missing for MSVC-like files
            if compiler == "Microsoft Visual C++ (MSVC)" and not rich_info["present"]:
                anomalies.append({
                    "type": "missing_rich_header",
                    "severity": "low",
                    "detail": "MSVC compiler indicators present but Rich Header is missing or stripped"
                })

            # Check if compilation timestamp is extremely old or pre-dates compiler version
            if pe.FILE_HEADER.TimeDateStamp < 946684800:  # Before Year 2000
                anomalies.append({
                    "type": "pre_2000_timestamp",
                    "severity": "medium",
                    "detail": "Linker timestamp is extremely old (pre-2000), common in evasion/spoofing"
                })

            result["compiler"] = compiler
            result["packer"] = packer
            result["rich_header"] = rich_info
            result["linker_info"] = linker_info
            result["anomalies"] = anomalies

        except Exception as exc:
            logger.exception("Error during packer detection of %s", pe_path)
            result["error"] = str(exc)
        finally:
            pe.close()

        return result
