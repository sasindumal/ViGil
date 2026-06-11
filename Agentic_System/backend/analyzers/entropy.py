"""
ViGil — PE Entropy & Packer Analyzer
====================================

Computes Shannon entropy for the entire file and individual sections,
analyzes packing likelihood, and matches known packer signatures.
"""

from __future__ import annotations

import math
import logging
from collections import Counter
from pathlib import Path
from typing import Any

import pefile

logger = logging.getLogger(__name__)

PACKER_SIGNATURES = {
    "UPX": [".upx0", ".upx1", ".upx2", "upx0", "upx1", "upx2"],
    "Themida": [".themida", "themida", "winlicense"],
    "VMProtect": [".vmp0", ".vmp1", ".vmp2", "vmp0", "vmp1", "vmp2"],
    "ASPack": [".aspack", "aspack", ".adata"],
    "PECompact": [".pecompat", "pecompact", ".pec"],
    "MPRESS": [".mpress", "mpress"],
}


class EntropyAnalyzer:
    """Computes Shannon entropy and identifies packing signatures/scores."""

    def analyze(self, pe_path: Path) -> dict[str, Any]:
        """Perform entropy and packer analysis on a PE file.

        Returns
        -------
        dict
            Shannon entropy values, section entropies, packer matches, and packing score.
        """
        result: dict[str, Any] = {
            "file_entropy": 0.0,
            "section_entropies": {},
            "entropy_class": "unknown",
            "packing_score": 0,
            "detected_packers": [],
        }

        try:
            with open(pe_path, "rb") as f:
                data = f.read()
            
            if not data:
                return result

            # Shannon Entropy for entire file
            file_entropy = self._shannon_entropy(data)
            result["file_entropy"] = round(file_entropy, 4)

            # Entropy classification
            if file_entropy < 1.0:
                result["entropy_class"] = "mostly empty"
            elif file_entropy < 5.0:
                result["entropy_class"] = "normal code/data"
            elif file_entropy < 7.0:
                result["entropy_class"] = "compressed/encoded"
            else:
                result["entropy_class"] = "encrypted/packed"

        except Exception as exc:
            logger.error("Failed to read file for entropy calculation %s: %s", pe_path, exc)
            result["error"] = str(exc)
            return result

        try:
            pe = pefile.PE(str(pe_path), fast_load=True)
        except Exception as exc:
            logger.error("Failed to parse PE for entropy section details %s: %s", pe_path, exc)
            result["error"] = str(exc)
            return result

        try:
            section_entropies = {}
            detected_packers = []
            packing_score = 0

            # 1. Per-section entropy and name matching
            high_entropy_sections = 0
            for section in pe.sections:
                try:
                    name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace").lower()
                except Exception:
                    name = section.Name.hex()

                sec_data = section.get_data()
                sec_entropy = self._shannon_entropy(sec_data)
                section_entropies[name] = round(sec_entropy, 4)

                if sec_entropy > 7.2:
                    high_entropy_sections += 1

                # Match packer names
                for packer, sigs in PACKER_SIGNATURES.items():
                    if any(sig in name for sig in sigs):
                        if packer not in detected_packers:
                            detected_packers.append(packer)

            result["section_entropies"] = section_entropies
            result["detected_packers"] = detected_packers

            # 2. Packing Likelihood Score Calculation
            # Heuristics:
            # - Matches packer signature: +50
            # - File entropy > 7.0: +30
            # - High entropy sections: +20 * count
            # - Less than 3 sections: +10
            if detected_packers:
                packing_score += 50
            if file_entropy > 7.0:
                packing_score += 30
            packing_score += high_entropy_sections * 20
            if len(pe.sections) < 3:
                packing_score += 10

            result["packing_score"] = min(packing_score, 100)

        except Exception as exc:
            logger.exception("Error during entropy analysis of %s", pe_path)
            result["error"] = str(exc)
        finally:
            pe.close()

        return result

    def _shannon_entropy(self, data: bytes) -> float:
        """Compute Shannon entropy of *data* (0.0 – 8.0)."""
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)
