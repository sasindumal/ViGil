"""
ViGil — PE Import Analyzer
============================

Extracts every imported DLL and function, computes the imphash, and maps
each API to behavioural threat categories (process injection, execution,
networking, crypto, anti-analysis, persistence, file operations).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pefile

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Behaviour classification tables
# ---------------------------------------------------------------------------
BEHAVIOR_CATEGORIES: dict[str, set[str]] = {
    "process_injection": {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtWriteVirtualMemory", "NtAllocateVirtualMemory",
        "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread",
        "NtMapViewOfSection", "SetThreadContext", "ResumeThread",
        "NtUnmapViewOfSection", "ZwWriteVirtualMemory",
    },
    "execution": {
        "WinExec", "ShellExecuteA", "ShellExecuteW",
        "ShellExecuteExA", "ShellExecuteExW",
        "CreateProcessA", "CreateProcessW",
        "CreateProcessInternalW", "CreateProcessAsUserA",
        "CreateProcessAsUserW", "CreateProcessWithLogonW",
        "system", "_wsystem",
    },
    "network": {
        "InternetOpenA", "InternetOpenW",
        "InternetOpenUrlA", "InternetOpenUrlW",
        "InternetConnectA", "InternetConnectW",
        "HttpOpenRequestA", "HttpOpenRequestW",
        "HttpSendRequestA", "HttpSendRequestW",
        "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
        "WinHttpOpenRequest",
        "URLDownloadToFileA", "URLDownloadToFileW",
        "URLDownloadToCacheFileA", "URLDownloadToCacheFileW",
        "WSAStartup", "socket", "connect", "send", "recv",
        "bind", "listen", "accept", "sendto", "recvfrom",
        "getaddrinfo", "gethostbyname",
    },
    "crypto": {
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
        "CryptImportKey", "CryptExportKey",
        "CryptAcquireContextA", "CryptAcquireContextW",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey",
        "BCryptOpenAlgorithmProvider",
        "CryptHashData", "CryptDeriveKey",
    },
    "anti_analysis": {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "NtQuerySystemInformation",
        "GetTickCount", "GetTickCount64",
        "QueryPerformanceCounter", "QueryPerformanceFrequency",
        "OutputDebugStringA", "OutputDebugStringW",
        "NtSetInformationThread", "NtClose",
        "FindWindowA", "FindWindowW",
    },
    "persistence": {
        "RegSetValueExA", "RegSetValueExW",
        "RegCreateKeyExA", "RegCreateKeyExW",
        "RegOpenKeyExA", "RegOpenKeyExW",
        "CreateServiceA", "CreateServiceW",
        "StartServiceA", "StartServiceW",
        "ChangeServiceConfigA", "ChangeServiceConfigW",
        "OpenSCManagerA", "OpenSCManagerW",
    },
    "file_operations": {
        "CreateFileA", "CreateFileW",
        "WriteFile", "ReadFile",
        "DeleteFileA", "DeleteFileW",
        "MoveFileA", "MoveFileW",
        "MoveFileExA", "MoveFileExW",
        "CopyFileA", "CopyFileW",
        "SetFileAttributesA", "SetFileAttributesW",
        "GetTempPathA", "GetTempPathW",
    },
}

# Flat look-up: function name → set of categories
_FUNC_TO_CATEGORIES: dict[str, list[str]] = {}
for _cat, _funcs in BEHAVIOR_CATEGORIES.items():
    for _fn in _funcs:
        _FUNC_TO_CATEGORIES.setdefault(_fn, []).append(_cat)


class ImportAnalyzer:
    """Extracts imports and classifies their behaviour."""

    def analyze(self, pe_path: Path) -> dict[str, Any]:
        """Analyze the import table of a PE file.

        Returns
        -------
        dict
            Keys: ``imports`` (per-DLL list), ``behavior_categories``,
            ``suspicious_apis``, ``imphash``, ``total_dlls``,
            ``total_functions``.
        """
        result: dict[str, Any] = {
            "imports": [],
            "behavior_categories": {cat: [] for cat in BEHAVIOR_CATEGORIES},
            "suspicious_apis": [],
            "imphash": None,
            "total_dlls": 0,
            "total_functions": 0,
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
            # imphash
            try:
                result["imphash"] = pe.get_imphash()
            except Exception:  # noqa: BLE001
                result["imphash"] = None

            imports_list: list[dict[str, Any]] = []
            suspicious: list[dict[str, Any]] = []
            categories_found: dict[str, list[str]] = {
                cat: [] for cat in BEHAVIOR_CATEGORIES
            }
            total_functions = 0

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="replace")
                    functions: list[dict[str, Any]] = []

                    for imp in entry.imports:
                        func_name = (
                            imp.name.decode("utf-8", errors="replace")
                            if imp.name
                            else None
                        )
                        ordinal = imp.ordinal
                        hint = imp.hint if hasattr(imp, "hint") else None

                        func_info: dict[str, Any] = {
                            "name": func_name,
                            "ordinal": ordinal,
                            "hint": hint,
                            "address": hex(imp.address) if imp.address else None,
                        }

                        # Classify
                        if func_name:
                            cats = _FUNC_TO_CATEGORIES.get(func_name, [])
                            if cats:
                                func_info["categories"] = cats
                                for c in cats:
                                    categories_found[c].append(
                                        f"{dll_name}!{func_name}"
                                    )
                                suspicious.append({
                                    "dll": dll_name,
                                    "function": func_name,
                                    "categories": cats,
                                })

                        functions.append(func_info)
                        total_functions += 1

                    imports_list.append({
                        "dll": dll_name,
                        "functions": functions,
                        "function_count": len(functions),
                    })

            # Delayed imports
            if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="replace")
                    functions = []
                    for imp in entry.imports:
                        func_name = (
                            imp.name.decode("utf-8", errors="replace")
                            if imp.name
                            else None
                        )
                        func_info = {
                            "name": func_name,
                            "ordinal": imp.ordinal,
                            "address": hex(imp.address) if imp.address else None,
                            "delayed": True,
                        }
                        if func_name:
                            cats = _FUNC_TO_CATEGORIES.get(func_name, [])
                            if cats:
                                func_info["categories"] = cats
                                for c in cats:
                                    categories_found[c].append(
                                        f"{dll_name}!{func_name} (delayed)"
                                    )
                                suspicious.append({
                                    "dll": dll_name,
                                    "function": func_name,
                                    "categories": cats,
                                    "delayed": True,
                                })
                        functions.append(func_info)
                        total_functions += 1

                    imports_list.append({
                        "dll": dll_name,
                        "functions": functions,
                        "function_count": len(functions),
                        "delayed": True,
                    })

            result["imports"] = imports_list
            result["behavior_categories"] = categories_found
            result["suspicious_apis"] = suspicious
            result["total_dlls"] = len(imports_list)
            result["total_functions"] = total_functions

        except Exception as exc:  # noqa: BLE001
            logger.exception("Error during import analysis of %s", pe_path)
            result["error"] = str(exc)
        finally:
            pe.close()

        return result
