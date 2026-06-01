"""
ViGiL — FastAPI Server
Endpoints: file upload, WebSocket progress, report retrieval, artifact downloads.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiofiles
from fastapi import FastAPI, File, UploadFile, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from loguru import logger

from config import settings
from models import AnalysisJob, JobStatus, AgentProgressEvent, VigilReport
from crew import run_pipeline

# ─────────────────────────────────────────────────────────────────────────────
# App Setup
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="ViGiL Malware Analysis API",
    description="Multi-agent malware analysis platform. Evidence-based verdicts, not ML black boxes.",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────────────────────
# In-memory job store (replace with Redis in production)
# ─────────────────────────────────────────────────────────────────────────────

jobs: dict[str, AnalysisJob] = {}
reports: dict[str, VigilReport] = {}
ws_connections: dict[str, list[WebSocket]] = {}


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket Progress Broadcaster
# ─────────────────────────────────────────────────────────────────────────────

async def broadcast_progress(event: AgentProgressEvent):
    """Send progress event to all connected WebSocket clients for this job."""
    job_id = event.job_id
    connections = ws_connections.get(job_id, [])
    dead = []
    message = event.model_dump_json()
    for ws in connections:
        try:
            await ws.send_text(message)
        except Exception:
            dead.append(ws)
    for ws in dead:
        connections.remove(ws)


# ─────────────────────────────────────────────────────────────────────────────
# Background Analysis Task
# ─────────────────────────────────────────────────────────────────────────────

async def run_analysis_task(job_id: str, file_path: Path):
    """Run the full pipeline in the background."""
    output_dir = settings.reports_dir / job_id
    output_dir.mkdir(parents=True, exist_ok=True)

    jobs[job_id].status = JobStatus.RUNNING

    try:
        report = await run_pipeline(
            job_id=job_id,
            file_path=file_path,
            output_dir=output_dir,
            progress_callback=broadcast_progress,
        )
        reports[job_id] = report
        jobs[job_id].status = JobStatus.COMPLETED
        jobs[job_id].completed_at = datetime.now(timezone.utc).isoformat()
        jobs[job_id].progress = 100

    except Exception as e:
        logger.exception(f"[Server] Analysis failed for job {job_id}: {e}")
        jobs[job_id].status = JobStatus.FAILED
        jobs[job_id].error = str(e)
        jobs[job_id].completed_at = datetime.now(timezone.utc).isoformat()

        # Send failure event to clients
        try:
            event = AgentProgressEvent(
                job_id=job_id,
                agent_name="Pipeline",
                agent_index=0,
                total_agents=17,
                status="failed",
                message=f"Analysis failed: {str(e)[:200]}",
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            await broadcast_progress(event)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "version": "1.0.0",
        "llm_provider": settings.llm_provider,
        "threat_intel_enabled": settings.threat_intel_enabled,
        "demo_mode": settings.demo_mode,
    }


@app.post("/api/analyze", response_model=AnalysisJob)
async def submit_analysis(file: UploadFile = File(...)):
    """
    Upload a PE file for analysis.
    Returns a job ID to track progress via WebSocket.
    """
    # Validate file size
    max_bytes = settings.max_file_size_mb * 1024 * 1024
    content = await file.read()
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {settings.max_file_size_mb}MB",
        )

    # Validate it's a PE file (MZ magic)
    if len(content) < 2 or content[:2] != b"MZ":
        raise HTTPException(
            status_code=400,
            detail="File does not appear to be a Windows PE executable (missing MZ header)",
        )

    # Save file
    job_id = str(uuid.uuid4())
    upload_path = settings.upload_dir / job_id
    upload_path.mkdir(parents=True, exist_ok=True)
    file_path = upload_path / (file.filename or "sample.exe")

    async with aiofiles.open(file_path, "wb") as f:
        await f.write(content)

    # Create job record
    job = AnalysisJob(
        job_id=job_id,
        filename=file.filename or "sample.exe",
        status=JobStatus.QUEUED,
        created_at=datetime.now(timezone.utc).isoformat(),
        progress=0,
    )
    jobs[job_id] = job

    # Start analysis in background
    asyncio.create_task(run_analysis_task(job_id, file_path))

    logger.info(f"[Server] Job {job_id} created for: {file.filename}")
    return job


@app.get("/api/job/{job_id}", response_model=AnalysisJob)
async def get_job_status(job_id: str):
    """Get current status of an analysis job."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs[job_id]


@app.get("/api/report/{job_id}")
async def get_report(job_id: str):
    """Get the full analysis report for a completed job."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    if jobs[job_id].status != JobStatus.COMPLETED:
        raise HTTPException(
            status_code=202,
            detail=f"Analysis not complete. Status: {jobs[job_id].status.value}",
        )

    if job_id not in reports:
        # Try loading from disk
        report_path = settings.reports_dir / job_id / "report.json"
        if report_path.exists():
            with open(report_path) as f:
                return JSONResponse(content=json.load(f))
        raise HTTPException(status_code=404, detail="Report not found")

    return JSONResponse(content=json.loads(reports[job_id].model_dump_json()))


@app.get("/api/download/{job_id}/{artifact}")
async def download_artifact(job_id: str, artifact: str):
    """
    Download a generated artifact.
    artifact: report_json | report_stix | yara | attack_navigator
    """
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    artifact_map = {
        "report_json": ("report.json", "application/json"),
        "report_stix": ("report.stix.json", "application/json"),
        "yara": ("generated.yara", "text/plain"),
        "attack_navigator": ("attack_layer.json", "application/json"),
    }

    if artifact not in artifact_map:
        raise HTTPException(status_code=400, detail=f"Unknown artifact: {artifact}. Valid: {list(artifact_map.keys())}")

    filename, media_type = artifact_map[artifact]
    file_path = settings.reports_dir / job_id / filename

    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"Artifact {artifact} not yet generated")

    return FileResponse(
        path=str(file_path),
        filename=filename,
        media_type=media_type,
    )


@app.get("/api/jobs")
async def list_jobs():
    """List all analysis jobs."""
    return list(jobs.values())


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket
# ─────────────────────────────────────────────────────────────────────────────

@app.websocket("/ws/{job_id}")
async def websocket_progress(websocket: WebSocket, job_id: str):
    """WebSocket endpoint for real-time analysis progress updates."""
    await websocket.accept()

    if job_id not in ws_connections:
        ws_connections[job_id] = []
    ws_connections[job_id].append(websocket)

    logger.info(f"[WebSocket] Client connected for job: {job_id}")

    # If job already completed, send the final status immediately
    if job_id in jobs:
        job = jobs[job_id]
        if job.status in (JobStatus.COMPLETED, JobStatus.FAILED):
            await websocket.send_text(json.dumps({
                "type": "job_status",
                "job_id": job_id,
                "status": job.status.value,
            }))

    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        if job_id in ws_connections:
            ws_connections[job_id].remove(websocket)
        logger.info(f"[WebSocket] Client disconnected for job: {job_id}")


# ─────────────────────────────────────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    logger.info("═" * 60)
    logger.info("  ViGiL — Multi-Agent Malware Analysis Platform v1.0.0")
    logger.info("═" * 60)
    logger.info(f"  LLM Provider: {settings.llm_provider}")
    logger.info(f"  Threat Intel: {'ENABLED' if settings.threat_intel_enabled else 'DEMO MODE'}")
    logger.info(f"  Vector Store: {settings.vector_store}")
    logger.info(f"  Upload Dir: {settings.upload_dir}")
    logger.info(f"  Reports Dir: {settings.reports_dir}")
    logger.info("═" * 60)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.vigil_host,
        port=settings.vigil_port,
        reload=settings.vigil_debug,
    )
