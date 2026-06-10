"""
ViGil Routes — Analysis Endpoints
==================================

Handles file uploading, analysis status checks, history querying,
and raw JSON results retrieval.
"""

from __future__ import annotations

import uuid
import logging
import asyncio
from pathlib import Path
from typing import Dict, Any

from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks

from backend.config import get_config
from backend.core.orchestrator import AnalysisOrchestrator
from backend.memory.long_term import LongTermMemory

logger = logging.getLogger("vigil.routes.analysis")

router = APIRouter(prefix="/api/analysis", tags=["Analysis"])

# Dict to track in-flight analyses
# ID → dict of status, progress, file_info, results, report
_analyses: Dict[str, dict[str, Any]] = {}


async def _run_bg_analysis(file_path: Path, analysis_id: str):
    """Background task to run orchestrator and save state."""
    _analyses[analysis_id] = {
        "status": "identifying",
        "progress": 0.0,
        "file_name": file_path.name,
        "file_size": file_path.stat().st_size,
        "results": None,
        "report": None,
    }

    try:
        orchestrator = AnalysisOrchestrator()
        results = await orchestrator.run_analysis(file_path, analysis_id)

        _analyses[analysis_id].update({
            "status": "completed",
            "progress": 1.0,
            "results": results,
            "report": results.get("report_markdown"),
        })

    except Exception as exc:
        logger.exception("Background analysis task failed for %s", analysis_id)
        _analyses[analysis_id].update({
            "status": "failed",
            "progress": 1.0,
            "error": str(exc),
        })

    finally:
        # Clean up target upload file to ensure safe operations
        try:
            if file_path.exists():
                file_path.unlink()
        except Exception:
            pass


@router.post("/upload")
async def upload_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """Upload a file for threat and vulnerability analysis."""
    cfg = get_config()
    upload_dir = cfg.storage.upload_dir
    upload_dir.mkdir(parents=True, exist_ok=True)

    analysis_id = str(uuid.uuid4())
    safe_name = "".join(c for c in file.filename if c.isalnum() or c in "._-")
    temp_path = upload_dir / f"{analysis_id}_{safe_name}"

    try:
        # Save file chunks to disk
        with open(temp_path, "wb") as f:
            while chunk := await file.read(65536):
                f.write(chunk)
    except Exception as exc:
        logger.error("Failed to save uploaded file: %s", exc)
        raise HTTPException(status_code=500, detail=f"File save error: {exc}")

    # Queue background task
    background_tasks.add_task(_run_bg_analysis, temp_path, analysis_id)

    return {
        "analysis_id": analysis_id,
        "file_name": file.filename,
        "file_size": temp_path.stat().st_size,
        "status": "queued",
    }


@router.get("/history")
async def get_history(limit: int = 50):
    """Retrieve history of completed analyses from SQLite."""
    ltm = LongTermMemory()
    await ltm.init_db()
    records = await ltm.get_recent_analyses(limit)
    return records


@router.get("/{analysis_id}")
async def get_status(analysis_id: str):
    """Check in-flight status or fetch results of a completed analysis."""
    # Check in-memory store first
    if analysis_id in _analyses:
        return _analyses[analysis_id]

    # Check long-term memory
    ltm = LongTermMemory()
    await ltm.init_db()
    record = await ltm.get_analysis(analysis_id)
    
    if not record:
        raise HTTPException(status_code=404, detail="Analysis ID not found.")

    return {
        "status": "completed",
        "progress": 1.0,
        "file_name": record.get("file_name"),
        "file_size": record.get("full_results_json", {}).get("file_size", 0),
        "results": record.get("full_results_json"),
        "report": record.get("report_markdown"),
    }


@router.get("/{analysis_id}/report")
async def get_report(analysis_id: str):
    """Get the markdown report for the specified analysis."""
    # Check in-memory
    if analysis_id in _analyses and _analyses[analysis_id]["report"]:
        return {"report_markdown": _analyses[analysis_id]["report"]}

    # Check LTM
    ltm = LongTermMemory()
    await ltm.init_db()
    record = await ltm.get_analysis(analysis_id)
    
    if not record:
        raise HTTPException(status_code=404, detail="Analysis ID not found.")

    return {"report_markdown": record.get("report_markdown")}


@router.get("/{analysis_id}/json")
async def get_json(analysis_id: str):
    """Get raw aggregated JSON results for the analysis."""
    if analysis_id in _analyses and _analyses[analysis_id]["results"]:
        return _analyses[analysis_id]["results"]

    ltm = LongTermMemory()
    await ltm.init_db()
    record = await ltm.get_analysis(analysis_id)
    
    if not record:
        raise HTTPException(status_code=404, detail="Analysis ID not found.")

    return record.get("full_results_json")


@router.delete("/{analysis_id}")
async def delete_analysis(analysis_id: str):
    """Delete an analysis record from memory and DB."""
    # Delete from in-memory
    _analyses.pop(analysis_id, None)

    # Delete from LTM
    ltm = LongTermMemory()
    await ltm.init_db()
    await ltm.delete_analysis(analysis_id)

    return {"status": "success", "message": f"Analysis {analysis_id} deleted."}
