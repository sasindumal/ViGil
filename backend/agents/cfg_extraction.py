"""
ViGiL — Agent 5: CFG Extraction Agent
Generates Control Flow Graph and Call Graph using angr (primary) with rizin fallback.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Optional

from loguru import logger

from models import CFGResult


def _run_with_angr(file_path: Path, output_dir: Path) -> Optional[dict]:
    """Generate CFG using angr."""
    try:
        import angr  # type: ignore
        import networkx  # type: ignore

        logger.info("[CFG] Loading binary with angr...")
        proj = angr.Project(str(file_path), auto_load_libs=False)

        # Recover CFG (fast mode for large binaries)
        cfg = proj.analyses.CFGFast(normalize=True)

        functions = []
        api_calls: dict[str, list[str]] = {}

        for func_addr, func in list(cfg.kb.functions.items())[:100]:
            # Only non-plt functions
            if func.is_plt:
                continue
            block_count = len(list(func.blocks))
            callers = [hex(c) for c in func.predecessors]
            callees = [hex(c) for c in func.successors]

            func_info = {
                "address": hex(func_addr),
                "name": func.name,
                "block_count": block_count,
                "callers": callers[:10],
                "callees": callees[:10],
                "suspicion_score": min(block_count / 5.0, 10.0),
            }
            functions.append(func_info)
            api_calls[func.name] = callees[:10]

        # Save CFG JSON
        cfg_json_path = output_dir / "cfg.json"
        cfg_data = {"functions": functions, "function_count": len(functions)}
        with open(cfg_json_path, "w") as f:
            json.dump(cfg_data, f, indent=2)

        callgraph_json_path = output_dir / "callgraph.json"
        with open(callgraph_json_path, "w") as f:
            json.dump(api_calls, f, indent=2)

        # Suspicious functions (high complexity)
        suspicious = sorted(functions, key=lambda x: x["suspicion_score"], reverse=True)[:10]

        avg_complexity = sum(f["block_count"] for f in functions) / max(len(functions), 1)

        return {
            "function_count": len(functions),
            "avg_complexity": round(avg_complexity, 2),
            "suspicious_functions": suspicious,
            "api_call_graph": api_calls,
            "cfg_json_path": str(cfg_json_path),
            "callgraph_json_path": str(callgraph_json_path),
        }

    except ImportError:
        logger.warning("[CFG] angr not installed")
    except Exception as e:
        logger.warning(f"[CFG] angr analysis failed: {e}")
    return None


def _run_with_rizin(file_path: Path, output_dir: Path) -> Optional[dict]:
    """Fallback CFG extraction using rizin (command line)."""
    try:
        result = subprocess.run(
            ["rizin", "-q", "-c", "aaa; aflj", str(file_path)],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            functions_raw = json.loads(result.stdout)
            functions = []
            for fn in functions_raw[:100]:
                functions.append({
                    "address": hex(fn.get("offset", 0)),
                    "name": fn.get("name", "unknown"),
                    "block_count": fn.get("nbbs", 1),
                    "callers": [],
                    "callees": [],
                    "suspicion_score": fn.get("cc", 1.0),
                })

            cfg_json_path = output_dir / "cfg.json"
            with open(cfg_json_path, "w") as f:
                json.dump({"functions": functions}, f, indent=2)

            avg_complexity = sum(f["block_count"] for f in functions) / max(len(functions), 1)
            suspicious = sorted(functions, key=lambda x: x["suspicion_score"], reverse=True)[:10]

            return {
                "function_count": len(functions),
                "avg_complexity": round(avg_complexity, 2),
                "suspicious_functions": suspicious,
                "api_call_graph": {},
                "cfg_json_path": str(cfg_json_path),
                "callgraph_json_path": None,
            }
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        logger.warning(f"[CFG] rizin failed: {e}")
    return None


def run_cfg_extraction(file_path: Path, output_dir: Path) -> CFGResult:
    logger.info(f"[CFG] Extracting control flow graph: {file_path.name}")

    result = _run_with_angr(file_path, output_dir)
    if not result:
        result = _run_with_rizin(file_path, output_dir)

    if not result:
        logger.warning("[CFG] No CFG extraction tool available — returning empty result")
        return CFGResult(
            function_count=0,
            avg_complexity=0.0,
            suspicious_functions=[],
            api_call_graph={},
        )

    return CFGResult(
        function_count=result["function_count"],
        avg_complexity=result["avg_complexity"],
        suspicious_functions=result["suspicious_functions"],
        api_call_graph=result["api_call_graph"],
        cfg_json_path=result.get("cfg_json_path"),
        callgraph_json_path=result.get("callgraph_json_path"),
    )
