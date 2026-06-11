"""
ViGil — PE Memory Layout Simulator
====================================

Simulates how the PE file loads into virtual memory based on the ImageBase
and section RVAs, details the Import Address Table (IAT) layout, counts
relocation table entries, and detects Thread Local Storage (TLS) callbacks
(which can execute code before the main entry point).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pefile

logger = logging.getLogger(__name__)


class MemoryLayoutAnalyzer:
    """Simulates binary virtual memory layout and extracts loading metadata."""

    def analyze(self, pe_path: Path) -> dict[str, Any]:
        """Simulate section virtual mapping and inspect IAT/TLS callbacks.

        Returns
        -------
        dict
            Virtual memory map, relocations count, IAT structure,
            and TLS callback entry points.
        """
        result: dict[str, Any] = {
            "memory_map": [],
            "relocations": {
                "present": False,
                "count": 0,
            },
            "iat_info": {
                "present": False,
                "entry_count": 0,
            },
            "tls_callbacks": [],
        }

        try:
            pe = pefile.PE(str(pe_path), fast_load=False)
        except Exception as exc:
            logger.error("Failed to parse PE in memory layout analyzer %s: %s", pe_path, exc)
            result["error"] = str(exc)
            return result

        try:
            image_base = pe.OPTIONAL_HEADER.ImageBase

            # 1. Virtual memory map simulation
            memory_map = []
            for section in pe.sections:
                try:
                    name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
                except Exception:
                    name = section.Name.hex()

                virt_start = image_base + section.VirtualAddress
                virt_end = virt_start + section.Misc_VirtualSize
                
                memory_map.append({
                    "section_name": name,
                    "virtual_address_range": f"{hex(virt_start)} - {hex(virt_end)}",
                    "virtual_size": section.Misc_VirtualSize,
                    "rva": hex(section.VirtualAddress),
                })
            result["memory_map"] = memory_map

            # 2. Relocation table analysis
            reloc_count = 0
            has_reloc = hasattr(pe, "DIRECTORY_ENTRY_BASERELOC")
            if has_reloc and pe.DIRECTORY_ENTRY_BASERELOC:
                for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
                    # Count individual reloc entries
                    if hasattr(base_reloc, "entries"):
                        reloc_count += len(base_reloc.entries)

            result["relocations"] = {
                "present": has_reloc,
                "count": reloc_count,
            }

            # 3. IAT info
            has_iat = hasattr(pe, "DIRECTORY_ENTRY_IMPORT")
            iat_entry_count = 0
            if has_iat and pe.DIRECTORY_ENTRY_IMPORT:
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    iat_entry_count += len(entry.imports)

            result["iat_info"] = {
                "present": has_iat,
                "entry_count": iat_entry_count,
            }

            # 4. TLS callbacks detection
            # TLS callbacks run code before AddressOfEntryPoint. Malware frequently uses them.
            tls_callbacks = []
            if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS and pe.DIRECTORY_ENTRY_TLS.struct:
                # Retrieve the table address of callbacks
                callbacks_addr = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
                if callbacks_addr:
                    # Walk through the list of callback addresses
                    # On x86 addresses are 4 bytes, on x64 they are 8 bytes
                    arch = pe.FILE_HEADER.Machine
                    ptr_size = 8 if arch == 0x8664 else 4
                    rva = callbacks_addr - image_base

                    idx = 0
                    while True:
                        try:
                            # Read callback pointer from file
                            ptr_data = pe.get_data(rva + (idx * ptr_size), ptr_size)
                            # Convert ptr_data bytes to int address
                            if len(ptr_data) < ptr_size:
                                break
                            ptr_val = int.from_bytes(ptr_data, "little")
                            if ptr_val == 0:
                                break
                            tls_callbacks.append(hex(ptr_val))
                            idx += 1
                        except Exception:
                            break

            result["tls_callbacks"] = tls_callbacks

        except Exception as exc:
            logger.exception("Error during memory layout simulation of %s", pe_path)
            result["error"] = str(exc)
        finally:
            pe.close()

        return result
