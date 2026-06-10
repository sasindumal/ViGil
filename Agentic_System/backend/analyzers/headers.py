"""
ViGil — PE Header Analyzer
===========================

Parses DOS, NT, and Optional headers from a PE file, extracting key fields
and detecting structural anomalies that may indicate packing, tampering,
or malicious intent.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pefile

logger = logging.getLogger(__name__)

# ASLR / DEP / CFG bitmask constants from the PE spec.
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080

# Well-known Machine type mappings.
MACHINE_TYPES: dict[int, str] = {
    0x0: "IMAGE_FILE_MACHINE_UNKNOWN",
    0x14C: "IMAGE_FILE_MACHINE_I386",
    0x8664: "IMAGE_FILE_MACHINE_AMD64",
    0x1C0: "IMAGE_FILE_MACHINE_ARM",
    0xAA64: "IMAGE_FILE_MACHINE_ARM64",
}

# Characteristics flag descriptions.
CHARACTERISTICS_FLAGS: dict[int, str] = {
    0x0001: "RELOCS_STRIPPED",
    0x0002: "EXECUTABLE_IMAGE",
    0x0004: "LINE_NUMS_STRIPPED",
    0x0008: "LOCAL_SYMS_STRIPPED",
    0x0020: "LARGE_ADDRESS_AWARE",
    0x0100: "32BIT_MACHINE",
    0x0200: "DEBUG_STRIPPED",
    0x1000: "SYSTEM",
    0x2000: "DLL",
}


class HeaderAnalyzer:
    """Analyzes DOS, NT, and Optional PE headers and flags anomalies."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def analyze(self, pe_path: Path) -> dict[str, Any]:
        """Parse PE headers and return a structured analysis dict.

        Parameters
        ----------
        pe_path:
            Filesystem path to the PE file to analyze.

        Returns
        -------
        dict
            Keys: ``dos_header``, ``nt_headers``, ``optional_header``,
            ``anomalies``.  On failure an ``error`` key is present and the
            other keys contain safe defaults.
        """
        result: dict[str, Any] = {
            "dos_header": {},
            "nt_headers": {},
            "optional_header": {},
            "anomalies": [],
        }

        try:
            pe = pefile.PE(str(pe_path), fast_load=True)
        except pefile.PEFormatError as exc:
            logger.error("Failed to parse PE headers for %s: %s", pe_path, exc)
            result["error"] = str(exc)
            return result
        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected error loading PE %s", pe_path)
            result["error"] = str(exc)
            return result

        try:
            anomalies: list[dict[str, str]] = []

            # ---- DOS Header ----
            dos = pe.DOS_HEADER
            result["dos_header"] = {
                "e_magic": hex(dos.e_magic),
                "e_magic_ascii": "MZ" if dos.e_magic == 0x5A4D else "INVALID",
                "e_lfanew": dos.e_lfanew,
            }
            if dos.e_magic != 0x5A4D:
                anomalies.append({
                    "type": "invalid_dos_magic",
                    "severity": "critical",
                    "detail": f"DOS e_magic is {hex(dos.e_magic)}, expected 0x5a4d",
                })

            # ---- NT Headers ----
            file_hdr = pe.FILE_HEADER
            timestamp_raw = file_hdr.TimeDateStamp
            timestamp_dt = datetime.fromtimestamp(timestamp_raw, tz=timezone.utc)

            machine_val = file_hdr.Machine
            machine_str = MACHINE_TYPES.get(machine_val, f"UNKNOWN(0x{machine_val:04X})")

            characteristics_raw = file_hdr.Characteristics
            characteristics_list = [
                desc
                for flag, desc in CHARACTERISTICS_FLAGS.items()
                if characteristics_raw & flag
            ]

            result["nt_headers"] = {
                "Signature": hex(pe.NT_HEADERS.Signature),
                "Machine": machine_str,
                "Machine_value": hex(machine_val),
                "TimeDateStamp": timestamp_raw,
                "TimeDateStamp_iso": timestamp_dt.isoformat(),
                "NumberOfSections": file_hdr.NumberOfSections,
                "Characteristics": hex(characteristics_raw),
                "Characteristics_flags": characteristics_list,
                "SizeOfOptionalHeader": file_hdr.SizeOfOptionalHeader,
                "PointerToSymbolTable": file_hdr.PointerToSymbolTable,
                "NumberOfSymbols": file_hdr.NumberOfSymbols,
            }

            # Timestamp anomalies
            now_ts = int(time.time())
            if timestamp_raw > now_ts:
                anomalies.append({
                    "type": "future_timestamp",
                    "severity": "high",
                    "detail": (
                        f"TimeDateStamp {timestamp_dt.isoformat()} is in the future"
                    ),
                })
            if timestamp_raw == 0:
                anomalies.append({
                    "type": "zero_timestamp",
                    "severity": "medium",
                    "detail": "TimeDateStamp is zero — likely tampered or generated",
                })

            # ---- Optional Header ----
            opt = pe.OPTIONAL_HEADER
            magic_map = {0x10B: "PE32", 0x20B: "PE32+"}
            magic_str = magic_map.get(opt.Magic, f"UNKNOWN(0x{opt.Magic:04X})")

            dll_chars = opt.DllCharacteristics
            aslr_enabled = bool(dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
            dep_enabled = bool(dll_chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
            cfg_enabled = bool(dll_chars & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
            no_seh = bool(dll_chars & IMAGE_DLLCHARACTERISTICS_NO_SEH)
            force_integrity = bool(dll_chars & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)

            subsystem_map = {
                0: "UNKNOWN", 1: "NATIVE", 2: "WINDOWS_GUI",
                3: "WINDOWS_CUI", 5: "OS2_CUI", 7: "POSIX_CUI",
                9: "WINDOWS_CE_GUI", 14: "EFI_APPLICATION",
            }
            subsystem_str = subsystem_map.get(
                opt.Subsystem, f"UNKNOWN({opt.Subsystem})"
            )

            result["optional_header"] = {
                "Magic": magic_str,
                "Magic_value": hex(opt.Magic),
                "AddressOfEntryPoint": hex(opt.AddressOfEntryPoint),
                "ImageBase": hex(opt.ImageBase),
                "SectionAlignment": opt.SectionAlignment,
                "FileAlignment": opt.FileAlignment,
                "Subsystem": subsystem_str,
                "Subsystem_value": opt.Subsystem,
                "DllCharacteristics": hex(dll_chars),
                "SizeOfImage": opt.SizeOfImage,
                "SizeOfCode": opt.SizeOfCode,
                "SizeOfInitializedData": opt.SizeOfInitializedData,
                "SizeOfUninitializedData": opt.SizeOfUninitializedData,
                "SizeOfHeaders": opt.SizeOfHeaders,
                "Checksum": hex(opt.CheckSum),
                "security_features": {
                    "ASLR": aslr_enabled,
                    "DEP": dep_enabled,
                    "CFG": cfg_enabled,
                    "NO_SEH": no_seh,
                    "FORCE_INTEGRITY": force_integrity,
                },
            }

            # --- Optional-header anomalies ---
            if opt.CheckSum == 0:
                anomalies.append({
                    "type": "missing_checksum",
                    "severity": "medium",
                    "detail": "PE Checksum is zero — common in unsigned binaries",
                })
            else:
                computed = pe.generate_checksum()
                if computed != opt.CheckSum:
                    anomalies.append({
                        "type": "checksum_mismatch",
                        "severity": "high",
                        "detail": (
                            f"Stored checksum {hex(opt.CheckSum)} != "
                            f"computed {hex(computed)}"
                        ),
                    })

            if not aslr_enabled:
                anomalies.append({
                    "type": "aslr_disabled",
                    "severity": "medium",
                    "detail": "ASLR (DYNAMIC_BASE) is not enabled",
                })
            if not dep_enabled:
                anomalies.append({
                    "type": "dep_disabled",
                    "severity": "medium",
                    "detail": "DEP / NX is not enabled",
                })

            # Entry point outside any section?
            ep_rva = opt.AddressOfEntryPoint
            ep_in_section = False
            for section in pe.sections:
                sec_start = section.VirtualAddress
                sec_end = sec_start + max(
                    section.Misc_VirtualSize, section.SizeOfRawData
                )
                if sec_start <= ep_rva < sec_end:
                    ep_in_section = True
                    break
            if not ep_in_section and ep_rva != 0:
                anomalies.append({
                    "type": "suspicious_entry_point",
                    "severity": "high",
                    "detail": (
                        f"Entry point {hex(ep_rva)} is outside all section "
                        "boundaries"
                    ),
                })

            result["anomalies"] = anomalies

        except Exception as exc:  # noqa: BLE001
            logger.exception("Error during header analysis of %s", pe_path)
            result["error"] = str(exc)
        finally:
            pe.close()

        return result
