"""
ViGiL — Agent 1: Sample Intake Agent
Validates PE format, computes hashes, extracts metadata.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Optional

from loguru import logger

from models import SampleIntakeResult, Architecture


def _compute_hashes(file_path: Path) -> dict[str, str]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
            md5.update(chunk)
            sha1.update(chunk)
    return {
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
    }


def _detect_architecture(pe) -> Architecture:
    """Map pefile machine type to Architecture enum."""
    try:
        machine = pe.FILE_HEADER.Machine
        if machine == 0x014C:
            return Architecture.X86
        elif machine == 0x8664:
            return Architecture.X64
        elif machine == 0x01C0:
            return Architecture.ARM
        elif machine == 0xAA64:
            return Architecture.ARM64
    except Exception:
        pass
    return Architecture.UNKNOWN


def run_sample_intake(file_path: Path) -> SampleIntakeResult:
    """
    Validate and fingerprint a PE file.
    Falls back to basic file info if pefile is not available.
    """
    logger.info(f"[SampleIntake] Analyzing: {file_path.name}")

    hashes = _compute_hashes(file_path)
    file_size = file_path.stat().st_size

    # Attempt full PE parsing
    try:
        import pefile  # type: ignore

        pe = pefile.PE(str(file_path))
        arch = _detect_architecture(pe)

        # Compile timestamp
        timestamp = None
        try:
            import datetime
            ts = pe.FILE_HEADER.TimeDateStamp
            if ts:
                timestamp = datetime.datetime.utcfromtimestamp(ts).isoformat() + "Z"
        except Exception:
            pass

        # Detect .NET
        is_dotnet = False
        try:
            is_dotnet = hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR")
        except Exception:
            pass

        # Subsystem
        subsystem = None
        try:
            subsystem = pefile.SUBSYSTEM_TYPE.get(
                pe.OPTIONAL_HEADER.Subsystem, "UNKNOWN"
            )
        except Exception:
            pass

        result = SampleIntakeResult(
            sha256=hashes["sha256"],
            md5=hashes["md5"],
            sha1=hashes["sha1"],
            file_size=file_size,
            file_type="PE32+" if arch == Architecture.X64 else "PE32",
            arch=arch,
            compile_timestamp=timestamp,
            is_pe=True,
            is_dll=pe.is_dll(),
            is_dotnet=is_dotnet,
            subsystem=subsystem,
            machine_type=str(pe.FILE_HEADER.Machine),
        )
        pe.close()
        return result

    except ImportError:
        logger.warning("[SampleIntake] pefile not installed — using basic analysis")
    except Exception as e:
        logger.warning(f"[SampleIntake] PE parsing failed: {e} — using basic analysis")

    # Fallback: basic header check
    with open(file_path, "rb") as f:
        magic = f.read(2)

    is_pe = magic == b"MZ"
    file_type = "PE (MZ)" if is_pe else "Unknown Binary"

    return SampleIntakeResult(
        sha256=hashes["sha256"],
        md5=hashes["md5"],
        sha1=hashes["sha1"],
        file_size=file_size,
        file_type=file_type,
        arch=Architecture.UNKNOWN,
        is_pe=is_pe,
        is_dll=False,
        is_dotnet=False,
    )
