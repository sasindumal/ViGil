"""
ViGil — PE Export Analyzer
===========================

Lists every exported function (name + ordinal), flags suspicious exports
that are common in malware DLLs, and infers DLL intent based on export
patterns.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pefile

logger = logging.getLogger(__name__)

# Exports frequently seen in malware DLLs.
SUSPICIOUS_EXPORT_NAMES: set[str] = {
    "ServiceMain", "SvcMain",
    "DllRegisterServer", "DllUnregisterServer",
    "DllInstall", "DllCanUnloadNow", "DllGetClassObject",
    "InstallHook", "SetHook", "UnhookWindowsHookEx",
    "StartService", "StopService",
    "DecryptPayload", "RunPayload", "ExecutePayload",
    "Init", "Run", "Start", "Execute",
    "DllEntryPoint",
    "ReflectiveLoader", "LoadDll",
}

# Intent classification based on common export names / patterns.
INTENT_PATTERNS: dict[str, list[str]] = {
    "com_server": ["DllRegisterServer", "DllUnregisterServer",
                   "DllGetClassObject", "DllCanUnloadNow"],
    "service_dll": ["ServiceMain", "SvcMain", "StartService", "StopService"],
    "hook_dll": ["InstallHook", "SetHook", "UnhookWindowsHookEx"],
    "reflective_loader": ["ReflectiveLoader", "LoadDll"],
    "payload_carrier": ["DecryptPayload", "RunPayload", "ExecutePayload"],
    "proxy_dll": [],  # detected by ordinal-only exports matching known DLLs
}


class ExportAnalyzer:
    """Analyzes PE export directory entries."""

    def analyze(self, pe_path: Path) -> dict[str, Any]:
        """Return structured export information.

        Returns
        -------
        dict
            Keys: ``exports``, ``suspicious_exports``, ``dll_intent``,
            ``export_dll_name``, ``total_exports``.
        """
        result: dict[str, Any] = {
            "exports": [],
            "suspicious_exports": [],
            "dll_intent": [],
            "export_dll_name": None,
            "total_exports": 0,
        }

        try:
            pe = pefile.PE(str(pe_path), fast_load=False)
        except pefile.PEFormatError as exc:
            logger.error("PE parse error for %s: %s", pe_path, exc)
            result["error"] = str(exc)
            return result
        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected error loading PE %s", pe_path)
            result["error"] = str(exc)
            return result

        try:
            if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                result["note"] = "No export directory found"
                return result

            export_dir = pe.DIRECTORY_ENTRY_EXPORT

            # DLL name from export directory
            if export_dir.struct.Name:
                try:
                    dll_name_rva = export_dir.struct.Name
                    result["export_dll_name"] = pe.get_string_at_rva(
                        dll_name_rva
                    ).decode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    pass

            exports_list: list[dict[str, Any]] = []
            suspicious: list[dict[str, Any]] = []
            ordinal_only_count = 0

            for exp in export_dir.symbols:
                func_name = (
                    exp.name.decode("utf-8", errors="replace")
                    if exp.name
                    else None
                )
                ordinal = exp.ordinal
                address = hex(exp.address) if exp.address else None

                # Detect forwarded exports
                forwarder = None
                if exp.forwarder:
                    forwarder = exp.forwarder.decode("utf-8", errors="replace")

                export_entry: dict[str, Any] = {
                    "name": func_name,
                    "ordinal": ordinal,
                    "address": address,
                    "forwarder": forwarder,
                }
                exports_list.append(export_entry)

                if func_name is None:
                    ordinal_only_count += 1

                # Suspicious check
                if func_name and func_name in SUSPICIOUS_EXPORT_NAMES:
                    suspicious.append({
                        "name": func_name,
                        "ordinal": ordinal,
                        "reason": f"'{func_name}' is a known suspicious export name",
                    })

            # Intent classification
            export_name_set = {
                e["name"] for e in exports_list if e["name"]
            }
            dll_intent: list[str] = []
            for intent, markers in INTENT_PATTERNS.items():
                if markers and any(m in export_name_set for m in markers):
                    dll_intent.append(intent)

            # Proxy DLL heuristic: many ordinal-only exports
            if ordinal_only_count > 10 and ordinal_only_count > len(exports_list) * 0.7:
                dll_intent.append("proxy_dll")

            # Generic DLL if we have exports but no specific intent
            if not dll_intent and exports_list:
                dll_intent.append("generic_library")

            result["exports"] = exports_list
            result["suspicious_exports"] = suspicious
            result["dll_intent"] = dll_intent
            result["total_exports"] = len(exports_list)
            result["ordinal_only_count"] = ordinal_only_count

        except Exception as exc:  # noqa: BLE001
            logger.exception("Error during export analysis of %s", pe_path)
            result["error"] = str(exc)
        finally:
            pe.close()

        return result
