"""
ViGiL — Agent 7: Emulation Analysis Agent
Safe behavioral analysis via Microsoft Speakeasy emulator (no real execution).
Falls back to heuristic API sequence analysis.
"""
from __future__ import annotations

from pathlib import Path
import re

from loguru import logger

from models import EmulationResult


# API → behavior mapping
BEHAVIOR_MAP = {
    # File operations
    "CreateFileA": "files_created",
    "CreateFileW": "files_created",
    "DeleteFileA": "files_deleted",
    "DeleteFileW": "files_deleted",
    # Registry
    "RegCreateKeyExA": "registry_keys_created",
    "RegCreateKeyExW": "registry_keys_created",
    "RegSetValueExA": "registry_keys_modified",
    "RegSetValueExW": "registry_keys_modified",
    # Network
    "WSAConnect": "network_connections",
    "connect": "network_connections",
    "InternetConnect": "network_connections",
    "WinHttpConnect": "network_connections",
    # Process
    "CreateProcessA": "processes_created",
    "CreateProcessW": "processes_created",
    "ShellExecuteA": "processes_created",
    "ShellExecuteW": "processes_created",
    # DLL
    "LoadLibraryA": "dlls_loaded",
    "LoadLibraryW": "dlls_loaded",
    # Persistence
    "RegSetValueExA": "persistence_actions",
    "CreateServiceA": "persistence_actions",
    "CreateServiceW": "persistence_actions",
}

PERSISTENCE_KEYS = [
    r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    r"SYSTEM\\CurrentControlSet\\Services",
]


def _run_speakeasy(file_path: Path) -> dict | None:
    """Run Speakeasy emulation and collect behavioral report."""
    try:
        import speakeasy  # type: ignore

        se = speakeasy.Speakeasy()
        module = se.load_module(str(file_path))
        se.run_module(module)
        report = se.get_report()
        return report
    except (ImportError, ModuleNotFoundError) as e:
        # speakeasy-emulator 1.5.11 depends on unicorn==1.0.2 which uses
        # pkg_resources / distutils — both removed in Python 3.12.
        # The heuristic fallback is used automatically.
        logger.warning(f"[Emulation] Speakeasy not available ({e}). Using heuristic fallback.")
    except Exception as e:
        logger.warning(f"[Emulation] Speakeasy failed: {e}")
    return None


def _parse_speakeasy_report(report: dict) -> EmulationResult:
    """Parse Speakeasy report into EmulationResult."""
    result = EmulationResult()
    api_calls = []

    for entry in report.get("apis", []):
        api_name = entry.get("api", {}).get("name", "")
        args = entry.get("args", [])
        api_calls.append(api_name)

        category = BEHAVIOR_MAP.get(api_name)
        if category == "files_created" and args:
            result.files_created.append(str(args[0]))
        elif category == "files_deleted" and args:
            result.files_deleted.append(str(args[0]))
        elif category == "registry_keys_created" and args:
            result.registry_keys_created.append(str(args[1]) if len(args) > 1 else "")
        elif category == "network_connections" and args:
            result.network_connections.append({"address": str(args[0])})
        elif category == "processes_created" and args:
            result.processes_created.append(str(args[0]))
        elif category == "dlls_loaded" and args:
            result.dlls_loaded.append(str(args[0]))

    # Extract domains from network activity
    for entry in report.get("network", {}).get("dns", []):
        result.domains_contacted.append(entry.get("query", ""))

    result.api_calls = api_calls[:100]
    return result


def _heuristic_emulation(static_imports: list, static_strings: list[str]) -> EmulationResult:
    """Build behavioral profile from static evidence when emulation unavailable."""
    logger.info("[Emulation] Using heuristic behavioral analysis (no emulator)")

    result = EmulationResult()
    all_imports: list[str] = []
    for imp in static_imports:
        if hasattr(imp, "functions"):
            all_imports.extend(imp.functions)
        elif isinstance(imp, dict):
            all_imports.extend(imp.get("functions", []))

    strings_joined = "\n".join(static_strings)

    # Infer behaviors
    if any(f in all_imports for f in ["CreateFileA", "CreateFileW"]):
        result.files_created.append("[inferred from CreateFile imports]")

    if any(f in all_imports for f in ["RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA"]):
        result.registry_keys_modified.append("[inferred from RegSetValueEx imports]")

    if any(f in all_imports for f in ["InternetConnect", "WinHttpConnect", "WSAConnect", "connect"]):
        result.network_connections.append({"type": "inferred from network imports"})

    if any(f in all_imports for f in ["CreateProcessA", "CreateProcessW"]):
        result.processes_created.append("[inferred from CreateProcess imports]")

    if any(f in all_imports for f in ["LoadLibraryA", "LoadLibraryW"]):
        result.dlls_loaded.append("[inferred from LoadLibrary imports]")

    # Extract domains from strings
    domain_re = re.compile(
        r"\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|io|xyz|ru|cn|top|cc)\b",
        re.IGNORECASE,
    )
    result.domains_contacted = list(set(domain_re.findall(strings_joined)))[:20]

    # Persistence inference
    for key in PERSISTENCE_KEYS:
        if key.lower().replace("\\\\", "\\") in strings_joined.lower():
            result.persistence_actions.append(f"Possible persistence via {key}")

    result.api_calls = all_imports[:100]
    return result


def run_emulation_analysis(
    file_path: Path,
    static_imports: list = None,
    static_strings: list[str] = None,
) -> EmulationResult:
    logger.info(f"[Emulation] Analyzing: {file_path.name}")

    # Try Speakeasy first
    speakeasy_report = _run_speakeasy(file_path)
    if speakeasy_report:
        return _parse_speakeasy_report(speakeasy_report)

    # Fallback
    return _heuristic_emulation(static_imports or [], static_strings or [])
