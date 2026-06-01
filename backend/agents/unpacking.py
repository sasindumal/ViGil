"""
ViGiL — Agent 3: Multi-Stage Unpacking Agent
Detects packers and attempts emulated unpacking via Speakeasy / Qiling / Unicorn.
"""
from __future__ import annotations

import math
import subprocess
from pathlib import Path

from loguru import logger

from models import UnpackingResult


# Known packer signatures (magic bytes / section names)
PACKER_SIGNATURES = {
    "UPX": [b"UPX0", b"UPX1", b"UPX2", b"UPX!"],
    "MPRESS": [b".MPRESS1", b".MPRESS2"],
    "ASPack": [b".aspack", b".adata"],
    "Themida": [b".themida", b".winlice"],
    "VMProtect": [b".vmp0", b".vmp1", b".vmp2"],
    "Enigma": [b".enigma1", b".enigma2"],
    "PECompact": [b"PEC2"],
    "NsPack": [b"nsp0", b"nsp1"],
    "ExeStealth": [b"ExeSt"],
}

HIGH_ENTROPY_THRESHOLD = 7.0
SUSPICIOUS_IMPORT_COUNT = 5  # fewer than this = likely packed


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def _detect_packer_signatures(raw: bytes) -> list[str]:
    """Check for known packer byte signatures."""
    found = []
    for packer, sigs in PACKER_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in raw.lower():
                found.append(packer)
                break
    return found


def _check_pe_heuristics(file_path: Path) -> dict:
    """PE-based heuristics: entropy, import count, RWX sections."""
    result = {
        "high_entropy_sections": [],
        "rwx_sections": False,
        "import_count": 999,
        "sections": [],
    }
    try:
        import pefile

        pe = pefile.PE(str(file_path))

        # Import count
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            result["import_count"] = len(pe.DIRECTORY_ENTRY_IMPORT)
        else:
            result["import_count"] = 0

        # Sections
        for s in pe.sections:
            data = s.get_data()
            ent = _entropy(data)
            name = s.Name.decode("utf-8", errors="replace").rstrip("\x00")
            result["sections"].append({"name": name, "entropy": ent})

            if ent > HIGH_ENTROPY_THRESHOLD:
                result["high_entropy_sections"].append(name)

            # RWX: IMAGE_SCN_MEM_READ | WRITE | EXECUTE
            if (s.Characteristics & 0xE0000000) == 0xE0000000:
                result["rwx_sections"] = True

        pe.close()
    except Exception as e:
        logger.debug(f"[Unpacking] PE heuristics failed: {e}")

    return result


def _try_upx_unpack(file_path: Path, output_dir: Path) -> bool:
    """Try unpacking with UPX binary."""
    output_path = output_dir / f"{file_path.stem}_unpacked.exe"
    try:
        result = subprocess.run(
            ["upx", "-d", "-o", str(output_path), str(file_path)],
            capture_output=True, timeout=30
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _try_speakeasy_emulation(file_path: Path) -> dict:
    """Attempt emulated unpacking via Speakeasy."""
    try:
        import speakeasy  # type: ignore

        se = speakeasy.Speakeasy()
        module = se.load_module(str(file_path))
        se.run_module(module)
        api_calls = [c["api"]["name"] for c in se.get_report().get("apis", [])]
        return {"success": True, "api_calls": api_calls[:50]}
    except ImportError:
        logger.debug("[Unpacking] Speakeasy not installed")
    except Exception as e:
        logger.debug(f"[Unpacking] Speakeasy emulation failed: {e}")
    return {"success": False, "api_calls": []}


def run_unpacking_analysis(file_path: Path, output_dir: Path) -> UnpackingResult:
    logger.info(f"[Unpacking] Analyzing: {file_path.name}")

    with open(file_path, "rb") as f:
        raw = f.read()

    # Stage 1: Signature detection
    detected_packers = _detect_packer_signatures(raw)

    # Stage 2: PE heuristics
    heuristics = _check_pe_heuristics(file_path)
    is_packed_heuristic = (
        bool(heuristics["high_entropy_sections"])
        or heuristics["import_count"] < SUSPICIOUS_IMPORT_COUNT
        or heuristics["rwx_sections"]
    )

    is_packed = bool(detected_packers) or is_packed_heuristic
    packer_name = detected_packers[0] if detected_packers else ("Unknown Packer" if is_packed else None)

    layers = 0
    payload_recovered = False
    layer_details = []

    if is_packed:
        logger.info(f"[Unpacking] Detected packer: {packer_name}")
        layers = 1

        # Stage 2a: UPX unpack
        if "UPX" in (detected_packers or []):
            unpacked = _try_upx_unpack(file_path, output_dir)
            if unpacked:
                layers = 1
                payload_recovered = True
                layer_details.append({"layer": 1, "packer": "UPX", "unpacked": True})

        # Stage 2b: Emulation
        if not payload_recovered:
            emu_result = _try_speakeasy_emulation(file_path)
            if emu_result["success"]:
                payload_recovered = True
                layer_details.append({
                    "layer": 1,
                    "method": "speakeasy_emulation",
                    "api_calls": emu_result["api_calls"],
                    "unpacked": True,
                })
            else:
                layer_details.append({
                    "layer": 1,
                    "packer": packer_name,
                    "method": "heuristic_detection_only",
                    "unpacked": False,
                })

        # Estimate layers for known multi-layer packers
        if packer_name in ("VMProtect", "Themida"):
            layers = 3
        elif packer_name == "ASPack":
            layers = 2

    return UnpackingResult(
        is_packed=is_packed,
        packer=packer_name,
        layers=layers,
        payload_recovered=payload_recovered,
        layer_details=layer_details,
        rwx_sections=heuristics["rwx_sections"],
        suspicious_import_count=heuristics["import_count"] < SUSPICIOUS_IMPORT_COUNT,
    )
