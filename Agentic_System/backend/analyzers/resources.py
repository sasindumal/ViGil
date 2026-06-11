"""
ViGil — PE Resource Analyzer
==============================

Analyzes the resource directory (.rsrc) of a PE file, enumerating resource types,
languages, detecting embedded executables, and extracting version information
metadata while flagging version spoofing or language anomalies.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pefile

logger = logging.getLogger(__name__)


class ResourceAnalyzer:
    """Analyzes PE resources for anomalies, spoofing, and embedded payloads."""

    SUSPICIOUS_COMPANIES = {
        "microsoft corporation": ["microsft", "micosoft", "microsof", "microsoft corp", "microsoft  corporation"],
        "google llc": ["gogle", "googe", "google inc", "google llc"],
    }

    def analyze(self, pe_path: Path) -> dict[str, Any]:
        """Analyze the resource section of a PE file.

        Returns
        -------
        dict
            Enumerated resources, version info, embedded PE status, and resource anomalies.
        """
        result: dict[str, Any] = {
            "resource_tree": [],
            "version_info": {},
            "embedded_executables": [],
            "anomalies": [],
            "total_resources": 0,
        }

        try:
            pe = pefile.PE(str(pe_path), fast_load=False)
        except pefile.PEFormatError as exc:
            logger.error("PE parse error for %s in resources: %s", pe_path, exc)
            result["error"] = str(exc)
            return result
        except Exception as exc:
            logger.exception("Unexpected error loading PE %s", pe_path)
            result["error"] = str(exc)
            return result

        try:
            anomalies = []
            embedded_exes = []
            resources_list = []

            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                # Walk the resource directory tree
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    # Get resource type name or ID
                    if resource_type.name is not None:
                        type_str = str(resource_type.name)
                    else:
                        type_str = pefile.RESOURCE_TYPE.get(resource_type.struct.Id, f"ID_{resource_type.struct.Id}")

                    if hasattr(resource_type, "directory"):
                        for resource_name in resource_type.directory.entries:
                            name_str = str(resource_name.name) if resource_name.name is not None else f"ID_{resource_name.struct.Id}"

                            if hasattr(resource_name, "directory"):
                                for resource_lang in resource_name.directory.entries:
                                    lang_id = resource_lang.struct.Id
                                    lang_name = pefile.LANG.get(lang_id & 0x3ff, f"LANG_{lang_id}")

                                    # Access data
                                    data_rva = resource_lang.data.struct.OffsetToData
                                    data_size = resource_lang.data.struct.Size
                                    
                                    try:
                                        res_data = pe.get_data(data_rva, data_size)
                                    except Exception:
                                        res_data = b""

                                    res_info = {
                                        "type": type_str,
                                        "name": name_str,
                                        "language": lang_name,
                                        "language_id": lang_id,
                                        "size": data_size,
                                        "rva": hex(data_rva),
                                    }
                                    resources_list.append(res_info)

                                    # Check for embedded executables (MZ signature)
                                    if res_data.startswith(b"MZ") or (b"PE\x00\x00" in res_data[:1024]):
                                        embedded_exes.append({
                                            "type": type_str,
                                            "name": name_str,
                                            "size": data_size,
                                            "rva": hex(data_rva),
                                            "magic": "MZ"
                                        })
                                        anomalies.append({
                                            "type": "embedded_pe_in_resource",
                                            "severity": "high",
                                            "detail": f"Embedded PE file found in resource {type_str}/{name_str} ({data_size} bytes)"
                                        })

                                    # Detect unusual language ID
                                    # E.g., malware frequently uses languages not aligned with typical distribution locales
                                    # 1049 is Russian, 2052 is Chinese, etc.
                                    if lang_id in [1049, 2052] and lang_id != 1033:  # 1033 is English (US)
                                        # This is a weak signal, categorized as low severity
                                        pass

            # Extract Version Information
            version_info = {}
            if hasattr(pe, "VS_VERSIONINFO"):
                for idx in range(len(pe.VS_VERSIONINFO)):
                    if hasattr(pe, "FileInfo") and len(pe.FileInfo) > idx:
                        for entry in pe.FileInfo[idx]:
                            if hasattr(entry, "StringTable"):
                                for st in entry.StringTable:
                                    for key, val in st.entries.items():
                                        k_str = key.decode("utf-8", errors="replace")
                                        v_str = val.decode("utf-8", errors="replace")
                                        version_info[k_str] = v_str

            # Check version info spoofing
            if version_info:
                comp_name = version_info.get("CompanyName", "").lower().strip()
                prod_name = version_info.get("ProductName", "").lower().strip()
                
                # Check for typo-squatting or suspicious CompanyName
                for correct, typos in self.SUSPICIOUS_COMPANIES.items():
                    # If the name is close to a major company but not correct
                    for typo in typos:
                        if typo in comp_name and comp_name != correct:
                            anomalies.append({
                                "type": "company_name_spoofing",
                                "severity": "high",
                                "detail": f"Suspicious CompanyName '{version_info.get('CompanyName')}' resembles '{correct}'"
                            })

                # Check for extreme mismatch between CompanyName and Product/File description
                if "microsoft" in comp_name and not ("microsoft" in prod_name or "windows" in prod_name or prod_name == ""):
                    # Weak signal of spoofing Microsoft metadata
                    anomalies.append({
                        "type": "suspicious_metadata_alignment",
                        "severity": "medium",
                        "detail": f"Company is '{version_info.get('CompanyName')}' but product is '{version_info.get('ProductName')}'"
                    })

            result["resource_tree"] = resources_list[:100]  # Cap list
            result["version_info"] = version_info
            result["embedded_executables"] = embedded_exes
            result["anomalies"] = anomalies
            result["total_resources"] = len(resources_list)

        except Exception as exc:
            logger.exception("Error during resource analysis of %s", pe_path)
            result["error"] = str(exc)
        finally:
            pe.close()

        return result
