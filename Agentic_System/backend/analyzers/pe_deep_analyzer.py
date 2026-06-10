"""
ViGil — Master PE Deep Analyzer
===============================

Aggregates all 15 Portable Executable (PE) analysis modules, executing them
in parallel using asyncio thread pools to extract DOS/NT/Optional headers,
sections, imports, exports, resources, entropy, Capstone CFG properties,
YARA signatures, debugging/anti-analysis features, certificate details,
overlay data, and memory layout.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from backend.analyzers.headers import HeaderAnalyzer
from backend.analyzers.sections import SectionAnalyzer
from backend.analyzers.imports_analysis import ImportAnalyzer
from backend.analyzers.exports_analysis import ExportAnalyzer
from backend.analyzers.strings_extractor import StringExtractor
from backend.analyzers.resources import ResourceAnalyzer
from backend.analyzers.entropy import EntropyAnalyzer
from backend.analyzers.cfg_analyzer import CFGAnalyzer
from backend.analyzers.api_call_graph import APICallGraphAnalyzer
from backend.analyzers.signatures import SignatureAnalyzer
from backend.analyzers.packer_detector import PackerDetector
from backend.analyzers.debug_features import DebugFeatureAnalyzer
from backend.analyzers.certificate import CertificateAnalyzer
from backend.analyzers.overlay import OverlayAnalyzer
from backend.analyzers.memory_layout import MemoryLayoutAnalyzer

from backend.core.event_emitter import EventType

logger = logging.getLogger(__name__)


class PEDeepAnalyzer:
    """Orchestrates the execution of all 15 individual PE analysis modules."""

    def __init__(self):
        self.analyzers = {
            "headers": HeaderAnalyzer(),
            "sections": SectionAnalyzer(),
            "imports": ImportAnalyzer(),
            "exports": ExportAnalyzer(),
            "strings": StringExtractor(),
            "resources": ResourceAnalyzer(),
            "entropy": EntropyAnalyzer(),
            "cfg": CFGAnalyzer(),
            "api_call_graph": APICallGraphAnalyzer(),
            "signatures": SignatureAnalyzer(),
            "packer": PackerDetector(),
            "debug_features": DebugFeatureAnalyzer(),
            "certificate": CertificateAnalyzer(),
            "overlay": OverlayAnalyzer(),
            "memory_layout": MemoryLayoutAnalyzer(),
        }

    async def analyze(self, pe_path: Path, event_emitter: Any = None, analysis_id: str = None) -> dict[str, Any]:
        """Run all 15 analysis modules in a thread pool and compile results.

        Parameters
        ----------
        pe_path:
            The file path of the PE to analyze.
        event_emitter:
            Optional WebSocket event emitter for streaming progress.
        analysis_id:
            Optional unique ID of the current analysis session.

        Returns
        -------
        dict
            Consolidated dictionary containing all analysis segments and status flags.
        """
        results: dict[str, Any] = {
            "file_name": pe_path.name,
            "file_size": pe_path.stat().st_size,
        }

        # List of tasks to run
        total_steps = len(self.analyzers)
        completed_steps = 0

        # Helper to run a synchronous analyzer in a thread pool and report progress
        async def run_one(name: str, analyzer: Any) -> tuple[str, dict[str, Any]]:
            nonlocal completed_steps
            if event_emitter and analysis_id:
                await event_emitter.emit_step(
                    analysis_id=analysis_id,
                    step="pe_analysis",
                    event_type=EventType.STEP_PROGRESS,
                    message=f"Running PE module: {name}...",
                    progress=round(completed_steps / total_steps, 2)
                )

            try:
                # Execute CPU/IO bound parser in executor thread
                res = await asyncio.get_event_loop().run_in_executor(
                    None, analyzer.analyze, pe_path
                )
            except Exception as exc:
                logger.error("Analyzer '%s' failed for %s: %s", name, pe_path.name, exc, exc_info=True)
                res = {"error": str(exc)}

            completed_steps += 1
            return name, res

        # Launch all tasks in parallel
        tasks = [run_one(name, analyzer) for name, analyzer in self.analyzers.items()]
        completed = await asyncio.gather(*tasks)

        # Merge results
        for name, res in completed:
            results[name] = res

        if event_emitter and analysis_id:
            await event_emitter.emit_step(
                analysis_id=analysis_id,
                step="pe_analysis",
                event_type=EventType.STEP_COMPLETED,
                message="PE Deep Analysis complete.",
                progress=1.0,
                data={"analysis_keys": list(self.analyzers.keys())}
            )

        return results
