"""
ViGil Routes — Report Retrieval Endpoints
==========================================

Enables retrieving analysis reports, downloading markdown reports as files,
and listing recent reports.
"""

from __future__ import annotations

import tempfile
import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from backend.memory.long_term import LongTermMemory

logger = logging.getLogger("vigil.routes.reports")

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.get("/recent")
async def get_recent_reports(limit: int = 20):
    """Retrieve list of recently generated threat reports."""
    ltm = LongTermMemory()
    await ltm.init_db()
    records = await ltm.get_recent_analyses(limit)
    return [
        {
            "analysis_id": r.get("id"),
            "file_name": r.get("file_name"),
            "file_type": r.get("file_type"),
            "verdict": r.get("verdict"),
            "risk_score": r.get("risk_score"),
            "created_at": r.get("created_at"),
        }
        for r in records
    ]


@router.get("/{analysis_id}")
async def get_report_content(analysis_id: str):
    """Get the markdown content of the report."""
    ltm = LongTermMemory()
    await ltm.init_db()
    record = await ltm.get_analysis(analysis_id)
    
    if not record or not record.get("report_markdown"):
        raise HTTPException(status_code=404, detail="Report not found for this analysis ID.")

    return {"report_markdown": record["report_markdown"]}


@router.get("/{analysis_id}/download")
async def download_report(analysis_id: str):
    """Download the report as a .md file."""
    ltm = LongTermMemory()
    await ltm.init_db()
    record = await ltm.get_analysis(analysis_id)
    
    if not record or not record.get("report_markdown"):
        raise HTTPException(status_code=404, detail="Report not found for this analysis ID.")

    # Write to a temporary file for response delivery
    report_content = record["report_markdown"]
    file_name = record.get("file_name", "vigil_threat_report")
    clean_name = "".join(c for c in file_name if c.isalnum() or c in "._-")
    
    # Create temp file
    temp_file = Path(tempfile.gettempdir()) / f"vigil_report_{analysis_id}.md"
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(report_content)
    except Exception as exc:
        logger.error("Failed to write temporary report file: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to generate download: {exc}")

    # Return FileResponse which handles file deletion or let it remain in temp
    return FileResponse(
        path=temp_file,
        filename=f"ViGil_Report_{clean_name}.md",
        media_type="text/markdown"
    )
