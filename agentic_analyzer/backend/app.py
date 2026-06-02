import os
import json
import uuid
import logging
import asyncio
import threading
from pathlib import Path
from typing import Dict, List, Any
from fastapi import FastAPI, UploadFile, File, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

# Add parent path for imports
import sys
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from uir.pipeline.processor import FileProcessor
from uir.config import UIRConfig
from agentic_analyzer.backend.config import Config
from agentic_analyzer.backend.chunker import CPGChunker
from agentic_analyzer.backend.analyzer import AgenticMalwareAnalyzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="ViGiL Agentic Malware Analysis Dashboard")

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Workspace directories
UPLOAD_DIR = Path(__file__).resolve().parent.parent / "uploads"
RUNS_DIR = Path(__file__).resolve().parent.parent / "runs"
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

for d in (UPLOAD_DIR, RUNS_DIR, FRONTEND_DIR):
    d.mkdir(parents=True, exist_ok=True)

# Active WebSocket connections
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, analysis_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[analysis_id] = websocket
        logger.info(f"WebSocket connected for analysis: {analysis_id}")

    def disconnect(self, analysis_id: str):
        if analysis_id in self.active_connections:
            del self.active_connections[analysis_id]
            logger.info(f"WebSocket disconnected for analysis: {analysis_id}")

    async def send_json(self, analysis_id: str, message: Dict[str, Any]):
        if analysis_id in self.active_connections:
            try:
                await self.active_connections[analysis_id].send_json(message)
            except Exception as e:
                logger.error(f"Error sending WebSocket message to {analysis_id}: {e}")
                self.disconnect(analysis_id)

manager = ConnectionManager()


def run_crewai_in_background(analysis_id: str, cpg_path: Path, loop: asyncio.AbstractEventLoop):
    """
    Background worker that segments the CPG, triggers CrewAI specialists,
    captures real-time logs, and publishes progress via the active event loop.
    """
    try:
        # Step 1: Segmentation
        asyncio.run_coroutine_threadsafe(
            manager.send_json(analysis_id, {
                "type": "status",
                "status": "chunking",
                "message": "CPG successfully generated. Initiating semantic decomposition and chunking..."
            }),
            loop
        )
        
        chunker = CPGChunker(cpg_path)
        chunks = chunker.chunk()
        
        # Step 2: Running analysis crew
        asyncio.run_coroutine_threadsafe(
            manager.send_json(analysis_id, {
                "type": "status",
                "status": "crew_running",
                "message": f"Decomposed into {len(chunks['behavioral_subgraphs'])} functional method blocks. Initializing 15 specialized LLM agents..."
            }),
            loop
        )
        
        # Define websocket callback to stream steps directly
        def web_callback(event_type: str, data: Dict[str, Any]):
            asyncio.run_coroutine_threadsafe(
                manager.send_json(analysis_id, {
                    "type": event_type,
                    "data": data
                }),
                loop
            )
            
        analyzer = AgenticMalwareAnalyzer(analysis_id, web_callback=web_callback)
        report = analyzer.analyze(chunks)
        
        # Step 3: Complete
        asyncio.run_coroutine_threadsafe(
            manager.send_json(analysis_id, {
                "type": "status",
                "status": "completed",
                "message": "Analysis successfully completed! Executive report compiled.",
                "report": report
            }),
            loop
        )
        
    except Exception as e:
        logger.error(f"Error in background crewai analysis for {analysis_id}: {e}", exc_info=True)
        asyncio.run_coroutine_threadsafe(
            manager.send_json(analysis_id, {
                "type": "status",
                "status": "failed",
                "message": f"Analysis failed: {str(e)}"
            }),
            loop
        )


@app.post("/api/analyze")
async def analyze_file(file: UploadFile = File(...)):
    """Receives binary, runs local UIR processing, and delegates to the CrewAI thread."""
    analysis_id = str(uuid.uuid4())
    
    # Save file upload
    temp_path = UPLOAD_DIR / f"{analysis_id}_{file.filename}"
    with open(temp_path, "wb") as f:
        f.write(await file.read())
        
    # Create run output directory
    run_dir = RUNS_DIR / analysis_id
    run_dir.mkdir(parents=True, exist_ok=True)
    cpg_path = run_dir / "extracted_file.cpg.json"
    
    # Initialize run info
    info = {
        "analysis_id": analysis_id,
        "filename": file.filename,
        "timestamp": datetime_str(),
        "status": "processing"
    }
    with open(run_dir / "info.json", "w") as f:
        json.dump(info, f)

    # We return the analysis_id immediately to the client so they can open WebSocket
    # The actual processing starts shortly after
    asyncio.create_task(process_pipeline(analysis_id, temp_path, cpg_path))
    
    return {"analysis_id": analysis_id, "filename": file.filename}


async def process_pipeline(analysis_id: str, temp_path: Path, cpg_path: Path):
    """Processes the UIR CPG pipeline then fires up the CrewAI background thread."""
    try:
        await asyncio.sleep(0.5) # Wait for client to connect to WebSocket
        
        # 1. Identification / Processing
        await manager.send_json(analysis_id, {
            "type": "status",
            "status": "processing",
            "message": f"Successfully uploaded. Starting UIR processing pipeline for {temp_path.name}..."
        })
        
        # Invoke actual UIR library
        uir_config = UIRConfig()
        uir_config.cpg_cache_dir = RUNS_DIR / analysis_id / "cpg_cache"
        uir_config.cpg_cache_dir.mkdir(parents=True, exist_ok=True)
        
        processor = FileProcessor(uir_config)
        cpg = processor.process(temp_path)
        
        if not cpg:
            raise ValueError("UIR processing failed to generate a valid Code Property Graph.")
            
        cpg.save(cpg_path)
        
        # Start CrewAI execution in a background thread to prevent blocking the event loop
        loop = asyncio.get_running_loop()
        thread = threading.Thread(
            target=run_crewai_in_background,
            args=(analysis_id, cpg_path, loop)
        )
        thread.daemon = True
        thread.start()
        
    except Exception as e:
        logger.error(f"Pipeline error for {analysis_id}: {e}", exc_info=True)
        await manager.send_json(analysis_id, {
            "type": "status",
            "status": "failed",
            "message": f"UIR CPG Pipeline failure: {str(e)}"
        })


@app.websocket("/ws/analyze/{analysis_id}")
async def websocket_endpoint(websocket: WebSocket, analysis_id: str):
    """Establish WebSockets mapping for live progressive streaming."""
    await manager.connect(analysis_id, websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(analysis_id)


@app.get("/api/report/{analysis_id}")
async def get_report(analysis_id: str):
    """Fetch report details and trace JSON logs."""
    run_dir = RUNS_DIR / analysis_id
    if not run_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis run not found")
        
    info_file = run_dir / "info.json"
    report_file = run_dir / "report.md"
    steps_file = run_dir / "steps.json"
    
    info = {}
    if info_file.exists():
        with open(info_file, "r") as f:
            info = json.load(f)
            
    report = ""
    if report_file.exists():
        with open(report_file, "r") as f:
            report = f.read()
            
    steps = []
    if steps_file.exists():
        with open(steps_file, "r") as f:
            steps = json.load(f)
            
    return {
        "info": info,
        "report": report,
        "steps": steps
    }


@app.get("/api/history")
async def get_history():
    """Retrieve full persistent runs database log."""
    history = []
    if RUNS_DIR.exists():
        for path in RUNS_DIR.iterdir():
            if path.is_dir():
                info_file = path / "info.json"
                if info_file.exists():
                    try:
                        with open(info_file, "r") as f:
                            info = json.load(f)
                        # Check if report exists to determine actual completeness
                        info["has_report"] = (path / "report.md").exists()
                        history.append(info)
                    except Exception:
                        pass
    # Sort by timestamp descending
    history.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return history


def datetime_str() -> str:
    from datetime import datetime
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# Mount the frontend directory static files at root
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
