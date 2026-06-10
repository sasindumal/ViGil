"""
ViGil — PE Section Analyzer
============================

Enumerates every section in a PE file, computes per-section entropy, flags
suspicious characteristics (RWX, high entropy, size mismatches, unusual
names), and produces a packing likelihood score.
"""

from __future__ import annotations

import logging
import math
from collections import Counter
from pathlib import Path
from typing import Any

import pefile

logger = logging.getLogger(__name__)

# Typical, well-known section names found in non-packed binaries.
KNOWN_SECTION_NAMES: set[str] = {
    ".text", ".rdata", ".data", ".bss", ".rsrc", ".reloc",
    ".idata", ".edata", ".pdata", ".tls", ".CRT", ".debug",
    ".sxdata", ".gfids", ".giats", ".00cfg", ".retplne",
}

# Section characteristic flags we care about.
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of *data* (0.0 – 8.0 for byte data)."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum(
        (c / total) * math.log2(c / total)
        for c in counts.values()
        if c > 0
    )


def _decode_section_name(raw: bytes) -> str:
    """Decode a section name from its raw bytes, stripping nulls."""
    try:
        return raw.rstrip(b"\x00").decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return raw.hex()


class SectionAnalyzer:
    """Analyzes PE sections for structural anomalies and packing indicators."""

    HIGH_ENTROPY_THRESHOLD: float = 7.2
    SIZE_MISMATCH_RATIO: float = 3.0  # virt/raw or raw/virt ratio

    def analyze(self, pe_path: Path) -> dict[str, Any]:
        """Return per-section details, red flags, and a packing score.

        Parameters
        ----------
        pe_path:
            Filesystem path to the PE file.

        Returns
        -------
        dict
            Keys: ``sections``, ``red_flags``, ``packing_likelihood``,
            ``total_sections``.
        """
        result: dict[str, Any] = {
            "sections": [],
            "red_flags": [],
            "packing_likelihood": 0,
            "total_sections": 0,
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
            sections_info: list[dict[str, Any]] = []
            red_flags: list[dict[str, str]] = []
            high_entropy_count = 0
            rwx_count = 0

            for section in pe.sections:
                name = _decode_section_name(section.Name)
                raw_data = section.get_data()
                entropy = _shannon_entropy(raw_data)

                virt_size = section.Misc_VirtualSize
                raw_size = section.SizeOfRawData
                virt_addr = section.VirtualAddress
                raw_addr = section.PointerToRawData
                chars = section.Characteristics

                is_exec = bool(chars & IMAGE_SCN_MEM_EXECUTE)
                is_read = bool(chars & IMAGE_SCN_MEM_READ)
                is_write = bool(chars & IMAGE_SCN_MEM_WRITE)
                is_code = bool(chars & IMAGE_SCN_CNT_CODE)
                is_init_data = bool(chars & IMAGE_SCN_CNT_INITIALIZED_DATA)
                is_uninit_data = bool(chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
                is_discardable = bool(chars & IMAGE_SCN_MEM_DISCARDABLE)
                is_rwx = is_read and is_write and is_exec

                sec_info: dict[str, Any] = {
                    "name": name,
                    "virtual_size": virt_size,
                    "virtual_address": hex(virt_addr),
                    "raw_size": raw_size,
                    "raw_address": hex(raw_addr),
                    "entropy": round(entropy, 4),
                    "characteristics": hex(chars),
                    "flags": {
                        "executable": is_exec,
                        "readable": is_read,
                        "writable": is_write,
                        "contains_code": is_code,
                        "contains_initialized_data": is_init_data,
                        "contains_uninitialized_data": is_uninit_data,
                        "discardable": is_discardable,
                        "rwx": is_rwx,
                    },
                }
                sections_info.append(sec_info)

                # ---- Red-flag detection ----
                if is_rwx:
                    rwx_count += 1
                    red_flags.append({
                        "type": "rwx_section",
                        "section": name,
                        "severity": "high",
                        "detail": f"Section '{name}' has Read+Write+Execute permissions",
                    })

                if entropy > self.HIGH_ENTROPY_THRESHOLD:
                    high_entropy_count += 1
                    red_flags.append({
                        "type": "high_entropy",
                        "section": name,
                        "severity": "high",
                        "detail": (
                            f"Section '{name}' entropy {entropy:.4f} exceeds "
                            f"{self.HIGH_ENTROPY_THRESHOLD} — likely packed/encrypted"
                        ),
                    })

                # Size mismatch
                if raw_size > 0 and virt_size > 0:
                    ratio = max(virt_size, raw_size) / max(min(virt_size, raw_size), 1)
                    if ratio > self.SIZE_MISMATCH_RATIO:
                        red_flags.append({
                            "type": "size_mismatch",
                            "section": name,
                            "severity": "medium",
                            "detail": (
                                f"Section '{name}' virtual/raw size ratio "
                                f"{ratio:.1f}x (virt={virt_size}, raw={raw_size})"
                            ),
                        })
                elif raw_size == 0 and virt_size > 0x1000:
                    red_flags.append({
                        "type": "size_mismatch",
                        "section": name,
                        "severity": "medium",
                        "detail": (
                            f"Section '{name}' has zero raw size but "
                            f"large virtual size ({virt_size})"
                        ),
                    })

                # Unusual section name
                if name and name not in KNOWN_SECTION_NAMES:
                    red_flags.append({
                        "type": "unusual_section_name",
                        "section": name,
                        "severity": "low",
                        "detail": f"Non-standard section name '{name}'",
                    })

            # ---- Packing likelihood score ----
            total = len(sections_info) or 1
            score = 0
            score += min(high_entropy_count * 25, 50)
            score += min(rwx_count * 20, 40)
            # Few sections (≤ 2) is a mild packing signal
            if total <= 2:
                score += 10
            score = min(score, 100)

            result["sections"] = sections_info
            result["red_flags"] = red_flags
            result["packing_likelihood"] = score
            result["total_sections"] = total

        except Exception as exc:  # noqa: BLE001
            logger.exception("Error during section analysis of %s", pe_path)
            result["error"] = str(exc)
        finally:
            pe.close()

        return result
