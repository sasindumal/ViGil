"""
ViGil — Master Analysis Orchestrator
=====================================

Coordinates the end-to-end analysis lifecycle:
1. File type identification (FileRouter)
2. Nested extraction of archives (RecursiveExtractor)
3. Deep PE parsing (PEDeepAnalyzer) + ML prediction (ModelPredictor)
4. AI Multi-Agent analysis (PEAnalysisCrew / ScriptAnalysisCrew)
5. Result aggregation, DB persistence, and real-time WebSocket event broadcasting.
"""

from __future__ import annotations

import sys
import hashlib
import logging
import tempfile
from pathlib import Path
from typing import Any

# Ensure parent ViGil directory is in sys.path
PARENT_DIR = str(Path(__file__).resolve().parent.parent.parent.parent)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from backend.config import get_config
from backend.core.file_router import FileRouter
from backend.core.event_emitter import get_emitter, EventType

from backend.analyzers.pe_deep_analyzer import PEDeepAnalyzer
from backend.ml.model_predictor import ModelPredictor
from backend.agents.pe_crew import PEAnalysisCrew
from backend.agents.script_crew import ScriptAnalysisCrew

from backend.memory.long_term import LongTermMemory
from backend.memory.knowledge_base import KnowledgeBase

from uir.extraction.recursive_engine import RecursiveExtractor

logger = logging.getLogger("vigil.orchestrator")


class AnalysisOrchestrator:
    """Coordinates the full static, ML, and agentic analysis pipeline."""

    def __init__(self):
        self.config = get_config()
        self.router = FileRouter()
        self.pe_analyzer = PEDeepAnalyzer()
        self.predictor = ModelPredictor()
        self.ltm = LongTermMemory()
        self.kb = KnowledgeBase()
        self.emitter = get_emitter()

    async def run_analysis(self, file_path: Path, analysis_id: str) -> dict[str, Any]:
        """Execute the complete ViGil malware analysis pipeline.

        Parameters
        ----------
        file_path:
            The local file path to analyze.
        analysis_id:
            A unique session ID (UUID).

        Returns
        -------
        dict
            The consolidated results dictionary containing all outputs.
        """
        logger.info("Starting orchestrator analysis for %s (ID: %s)", file_path.name, analysis_id[:8])
        await self.emitter.emit_step(
            analysis_id=analysis_id,
            step="initialization",
            event_type=EventType.ANALYSIS_STARTED,
            message=f"Beginning analysis of {file_path.name}...",
            progress=0.0
        )

        # 0. Initialize databases
        await self.ltm.init_db()

        # Compute SHA256 of the input file
        file_hash = self._compute_sha256(file_path)

        # 1. Lookup in Long Term Memory to avoid redundant analysis
        existing = await self.ltm.get_analysis_by_hash(file_hash)
        if existing:
            logger.info("Found cached analysis for hash %s in LTM", file_hash)
            await self.emitter.emit_step(
                analysis_id=analysis_id,
                step="caching",
                event_type=EventType.ANALYSIS_COMPLETED,
                message="Cached analysis results retrieved from memory.",
                progress=1.0,
                data={
                    "cached": True,
                    "verdict": existing.get("verdict"),
                    "risk_score": existing.get("risk_score"),
                }
            )
            # Reconstruct format
            return existing["full_results_json"]

        # 2. Identify File Route
        route_res = self.router.identify_and_route(file_path)
        route = route_res.get("route", "unsupported")

        await self.emitter.emit_step(
            analysis_id=analysis_id,
            step="routing",
            event_type=EventType.FILE_IDENTIFIED,
            message=f"File identified as {route_res.get('file_type')} ({route_res.get('category')})",
            progress=0.1,
            data=route_res
        )

        # Maintain files to process
        pe_files: list[Path] = []
        script_files: list[Path] = []
        temp_dirs: list[Path] = []

        # 3. Extraction (if container)
        if route == "container":
            await self.emitter.emit_step(
                analysis_id=analysis_id,
                step="extraction",
                event_type=EventType.STEP_STARTED,
                message="Container file detected. Unpacking nested archives recursively...",
                progress=0.15
            )

            # Temp output directory
            extract_dir = Path(tempfile.mkdtemp(prefix="vigil_extract_"))
            temp_dirs.append(extract_dir)

            try:
                # Call recursive extractor from UIR
                extractor = RecursiveExtractor()
                ext_res = extractor.extract(file_path, extract_dir)
                
                # Filter leaf files
                for f in ext_res.leaf_files:
                    f_route = self.router.identify_and_route(f.path)
                    if f_route.get("route") == "pe":
                        pe_files.append(f.path)
                    elif f_route.get("route") == "script":
                        script_files.append(f.path)

                await self.emitter.emit_step(
                    analysis_id=analysis_id,
                    step="extraction",
                    event_type=EventType.FILES_EXTRACTED,
                    message=f"Extraction completed. Extracted {len(ext_res.leaf_files)} files. Found {len(pe_files)} PE files and {len(script_files)} scripts.",
                    progress=0.3,
                    data={"extracted_count": len(ext_res.leaf_files), "pe_count": len(pe_files), "script_count": len(script_files)}
                )

            except Exception as exc:
                logger.error("Recursive extraction failed: %s", exc)
                await self.emitter.emit_step(
                    analysis_id=analysis_id,
                    step="extraction",
                    event_type=EventType.STEP_FAILED,
                    message=f"Extraction failed: {exc}",
                    progress=0.3
                )
        elif route == "pe":
            pe_files.append(file_path)
        elif route == "script":
            script_files.append(file_path)

        # 4. Process all PEs
        pe_results_list = []
        for pf in pe_files:
            pf_hash = self._compute_sha256(pf)
            # Run Deep PE Static Parser
            pe_json = await self.pe_analyzer.analyze(pf, self.emitter, analysis_id)
            await self.emitter.emit(self.emitter._history[analysis_id][-1])  # Ensure latest progress sent
            
            # Run ML Model
            await self.emitter.emit_step(
                analysis_id=analysis_id,
                step="ml_prediction",
                event_type=EventType.STEP_STARTED,
                message=f"Running joint model ML inference on {pf.name}...",
                progress=0.5
            )
            
            # Lazy load and predict
            ml_pred = await self.predictor.predict(pf)
            
            await self.emitter.emit_step(
                analysis_id=analysis_id,
                step="ml_prediction",
                event_type=EventType.STEP_COMPLETED,
                message=f"ML Prediction complete: {ml_pred.get('label')} with {ml_pred.get('confidence')*100:.2f}% confidence",
                progress=0.6,
                data=ml_pred
            )

            # Run PE Agent Crew
            pe_crew = PEAnalysisCrew()
            crew_res = await pe_crew.run(pe_json, ml_pred, self.emitter, analysis_id)

            pe_results_list.append({
                "file_name": pf.name,
                "file_hash": pf_hash,
                "static_analysis": pe_json,
                "ml_prediction": ml_pred,
                "agent_analysis": crew_res,
            })

        # 5. Process all Scripts
        script_results_list = []
        for sf in script_files:
            sf_hash = self._compute_sha256(sf)
            try:
                with open(sf, encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except Exception:
                content = ""

            script_crew = ScriptAnalysisCrew()
            crew_res = await script_crew.run(content, sf.name, self.emitter, analysis_id)

            script_results_list.append({
                "file_name": sf.name,
                "file_hash": sf_hash,
                "agent_analysis": crew_res,
            })

        # 6. Aggregate results
        final_verdict = "BENIGN"
        max_risk_score = 0.0
        confidence = 0.0
        merged_report = ""

        # Aggregate PE findings
        for pe_res in pe_results_list:
            crew_res = pe_res["agent_analysis"]
            if crew_res.get("verdict") == "MALWARE":
                final_verdict = "MALWARE"
            max_risk_score = max(max_risk_score, crew_res.get("risk_score", 0.0))
            confidence = max(confidence, crew_res.get("confidence", 0.0))
            merged_report += f"\n\n# PE Analysis: {pe_res['file_name']}\n" + crew_res.get("report_markdown", "")

        # Aggregate Script findings
        for script_res in script_results_list:
            crew_res = script_res["agent_analysis"]
            if crew_res.get("verdict") == "MALWARE":
                final_verdict = "MALWARE"
            max_risk_score = max(max_risk_score, crew_res.get("risk_score", 0.0))
            confidence = max(confidence, crew_res.get("confidence", 0.0))
            merged_report += f"\n\n# Script Analysis: {script_res['file_name']}\n" + crew_res.get("report_markdown", "")

        # Handle case where no files were processed
        if not pe_results_list and not script_results_list:
            final_verdict = "BENIGN"
            max_risk_score = 0.0
            confidence = 100.0
            merged_report = "The submitted file was empty or is of an unsupported type, and contained no analyzed components."

        final_results = {
            "analysis_id": analysis_id,
            "file_name": file_path.name,
            "file_hash": file_hash,
            "route": route,
            "verdict": final_verdict,
            "risk_score": max_risk_score,
            "confidence": confidence,
            "pe_results": pe_results_list,
            "script_results": script_results_list,
            "report_markdown": merged_report,
        }

        # 7. Persist to LTM (SQLite)
        await self.ltm.store_analysis(
            analysis_id=analysis_id,
            file_hash=file_hash,
            file_name=file_path.name,
            file_type=route,
            verdict=final_verdict,
            confidence=confidence,
            risk_score=max_risk_score,
            results=final_results,
            report=merged_report
        )

        # Track any extracted IOCs in entity memory / LTM
        iocs_to_save = []
        for pe_res in pe_results_list:
            strings = pe_res["static_analysis"].get("strings", {})
            for url in strings.get("urls", []):
                iocs_to_save.append({"type": "url", "value": url, "context": "Extracted URL from PE strings"})
            for ip in strings.get("ip_addresses", []):
                iocs_to_save.append({"type": "ip", "value": ip, "context": "Extracted IP from PE strings"})
        await self.ltm.store_iocs(analysis_id, iocs_to_save)

        # 8. Update system knowledge base
        for pe_res in pe_results_list:
            self.kb.update_from_analysis({
                "file_name": pe_res["file_name"],
                "file_size": file_path.stat().st_size,
                "pe_analysis": pe_res["static_analysis"]
            })

        # 9. Clean up temp extraction dirs
        for td in temp_dirs:
            try:
                import shutil
                shutil.rmtree(td)
            except Exception:
                pass

        # Final Event
        await self.emitter.emit_step(
            analysis_id=analysis_id,
            step="complete",
            event_type=EventType.ANALYSIS_COMPLETED,
            message="Analysis completed successfully.",
            progress=1.0,
            data={"verdict": final_verdict, "risk_score": max_risk_score}
        )

        return final_results

    def _compute_sha256(self, file_path: Path) -> str:
        """Compute SHA256 of a file."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as fh:
            while chunk := fh.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
