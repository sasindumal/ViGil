"""
ViGil — PE Overlay Data Analyzer
=================================

Calculates the actual boundary of a PE file, detects any appended overlay
data after the last section, computes its entropy, and scans for embedded
executables (MZ header) or archive file headers inside the overlay.
"""

from __future__ import annotations

import math
import logging
from collections import Counter
from pathlib import Path
from typing import Any

import pefile

logger = logging.getLogger(__name__)


class OverlayAnalyzer:
    """Detects and inspects overlay data appended after the PE structure."""

    def analyze(self, pe_path: Path) -> dict[str, Any]:
        """Check for overlay data and scan for embedded payloads.

        Returns
        -------
        dict
            has_overlay flag, overlay_size, overlay_entropy,
            embedded_pe flag, and detected archive signatures.
        """
        result: dict[str, Any] = {
            "has_overlay": False,
            "overlay_size": 0,
            "overlay_entropy": 0.0,
            "overlay_offset": 0,
            "embedded_pe": False,
            "archive_detected": False,
        }

        try:
            pe = pefile.PE(str(pe_path), fast_load=True)
        except Exception as exc:
            logger.error("Failed to parse PE in overlay analyzer %s: %s", pe_path, exc)
            result["error"] = str(exc)
            return result

        try:
            # 1. Get file size
            file_size = pe_path.stat().st_size

            # 2. Calculate the end of the PE file
            # PE end is the maximum of (PointerToRawData + SizeOfRawData) for all sections
            pe_end = 0
            for section in pe.sections:
                section_end = section.PointerToRawData + section.SizeOfRawData
                if section_end > pe_end:
                    pe_end = section_end

            # Check if there is data after the PE sections
            if file_size > pe_end:
                overlay_size = file_size - pe_end
                
                # Baseline check: only count as overlay if it is larger than 64 bytes
                # (to account for small compiler alignments / trailing padding)
                if overlay_size > 64:
                    result["has_overlay"] = True
                    result["overlay_size"] = overlay_size
                    result["overlay_offset"] = pe_end

                    # Read overlay data
                    with open(pe_path, "rb") as f:
                        f.seek(pe_end)
                        overlay_data = f.read(overlay_size)

                    # Compute entropy
                    result["overlay_entropy"] = round(self._shannon_entropy(overlay_data), 4)

                    # Check for embedded PE (MZ)
                    if overlay_data.startswith(b"MZ") or b"PE\x00\x00" in overlay_data[:1024]:
                        result["embedded_pe"] = True

                    # Check for common archive signatures
                    # ZIP (PK..), RAR (Rar!), 7z (7z..)
                    if overlay_data.startswith(b"PK\x03\x04"):
                        result["archive_detected"] = "ZIP"
                    elif overlay_data.startswith(b"Rar!\x1a\x07"):
                        result["archive_detected"] = "RAR"
                    elif overlay_data.startswith(b"7z\xbc\xaf\x27\x1c"):
                        result["archive_detected"] = "7z"
                    elif overlay_data.startswith(b"\x1f\x8b\x08"):
                        result["archive_detected"] = "GZIP"

        except Exception as exc:
            logger.exception("Error during overlay analysis of %s", pe_path)
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
