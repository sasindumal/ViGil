"""
ViGil — Knowledge Base
======================

JSON file-backed persistent knowledge base representing compiled malware signatures,
TTPs, evasion frequencies, and observed behavioral chains.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

# Import config
from backend.config import get_config

logger = logging.getLogger("vigil.memory.knowledge_base")


class KnowledgeBase:
    """Accumulates patterns, signatures, and TTPs learned from analyzed samples."""

    _instance: Optional[KnowledgeBase] = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.kb_path = get_config().storage.knowledge_base
        self.kb_path.parent.mkdir(parents=True, exist_ok=True)
        self.data: dict[str, Any] = {
            "malware_families": {},
            "ttps": {},
            "evasion_techniques": {},
            "behavioral_patterns": [],
            "ioc_patterns": {},
        }
        self.load()

    def load(self):
        """Load the knowledge base from disk."""
        if self.kb_path.exists():
            try:
                with open(self.kb_path) as f:
                    self.data = json.load(f)
                logger.info("Loaded Knowledge Base from %s", self.kb_path)
            except Exception as exc:
                logger.error("Failed to parse Knowledge Base JSON %s: %s", self.kb_path, exc)
        else:
            self.save()

    def save(self):
        """Save the knowledge base to disk."""
        try:
            with open(self.kb_path, "w") as f:
                json.dump(self.data, f, indent=2, default=str)
            logger.debug("Persisted Knowledge Base to %s", self.kb_path)
        except Exception as exc:
            logger.error("Failed to write Knowledge Base to %s: %s", self.kb_path, exc)

    def add_finding(self, category: str, key: str, value: Any):
        """Add or merge a new finding into a KB category."""
        if category not in self.data:
            self.data[category] = {}

        if isinstance(self.data[category], dict):
            if key in self.data[category]:
                # Merge logic depending on types
                if isinstance(self.data[category][key], list):
                    if value not in self.data[category][key]:
                        self.data[category][key].append(value)
                elif isinstance(self.data[category][key], dict) and isinstance(value, dict):
                    self.data[category][key].update(value)
                else:
                    self.data[category][key] = value
            else:
                self.data[category][key] = value
        elif isinstance(self.data[category], list):
            if value not in self.data[category]:
                self.data[category].append(value)
        
        self.save()

    def query(self, category: str, keyword: Optional[str] = None) -> list[Any]:
        """Query elements of a category, optionally filtering by keyword."""
        cat_data = self.data.get(category, {})
        if not cat_data:
            return []

        results = []
        if isinstance(cat_data, dict):
            for k, v in cat_data.items():
                if keyword is None or keyword.lower() in k.lower() or keyword.lower() in str(v).lower():
                    results.append({"key": k, "value": v})
        elif isinstance(cat_data, list):
            for item in cat_data:
                if keyword is None or keyword.lower() in str(item).lower():
                    results.append(item)
        return results

    def get_known_families(self) -> list[str]:
        """Return all compiled malware family names."""
        return list(self.data.get("malware_families", {}).keys())

    def get_known_ttps(self) -> list[str]:
        """Return all mapped MITRE ATT&CK technique IDs/names."""
        return list(self.data.get("ttps", {}).keys())

    def update_from_analysis(self, analysis_results: dict[str, Any]):
        """Extract and record learned patterns from a completed analysis session."""
        # 1. Extract malware family signature findings
        pe_sigs = analysis_results.get("pe_analysis", {}).get("signatures", {})
        matched_families = pe_sigs.get("matched_families", [])
        for family in matched_families:
            self.add_finding("malware_families", family, {
                "last_seen_file": analysis_results.get("file_name"),
                "sample_size": analysis_results.get("file_size"),
            })

        # 2. Extract evasion techniques frequency
        pe_evasion = analysis_results.get("pe_analysis", {}).get("debug_features", {})
        for debug_api in pe_evasion.get("anti_debug_apis", []):
            freq = self.data.setdefault("evasion_techniques", {}).get(debug_api, 0)
            self.add_finding("evasion_techniques", debug_api, freq + 1)

        # 3. Extract C2 or file IOC patterns
        strings = analysis_results.get("pe_analysis", {}).get("strings", {})
        for url in strings.get("urls", []):
            try:
                domain = url.split("//")[1].split("/")[0]
                freq = self.data.setdefault("ioc_patterns", {}).get(domain, 0)
                self.add_finding("ioc_patterns", domain, freq + 1)
            except Exception:
                pass

        self.save()
        logger.info("Knowledge Base updated from analysis of %s", analysis_results.get("file_name"))
class_name = "KnowledgeBase"
