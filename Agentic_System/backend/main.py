"""
ViGil Agentic System — FastAPI Entry Point
==========================================

Initializes the API application, configures CORS policies, registers
routes for upload, settings, reports, and WebSockets, and handles startup/shutdown events.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Config and routing imports
from backend.config import get_config
from backend.routes.analysis import router as analysis_router
from backend.routes.settings import router as settings_router
from backend.routes.reports import router as reports_router
from backend.routes.websocket import router as ws_router
from backend.ml.model_predictor import ModelPredictor

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("vigil.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle event manager for FastAPI application."""
    logger.info("Starting ViGil backend service...")
    
    # 1. Initialize configurations and create storage directories
    cfg = get_config()
    cfg.init()
    logger.info("Storage directories initialized: %s", cfg.storage.upload_dir)

    # 2. Trigger lazy loading of the ML Predictor model checkpoint
    predictor = ModelPredictor()
    # We load the model in the background at startup so it's ready when the user uploads a file
    asyncio.create_task(predictor.load_model())

    yield

    logger.info("Shutting down ViGil backend service...")


app = FastAPI(
    title="ViGil Agentic Malware Analysis System",
    description="Multi-agent and ML-powered threat classification and vulnerability extraction engine.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS Middleware
cfg = get_config()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[cfg.server.frontend_url, "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(analysis_router)
app.include_router(settings_router)
app.include_router(reports_router)
app.include_router(ws_router)


@app.get("/")
async def get_system_status():
    """Return central status metrics of the analysis engine."""
    predictor = ModelPredictor()
    cfg = get_config()
    return {
        "status": "online",
        "title": app.title,
        "active_llm_provider": cfg.llm.active_provider,
        "ml_model_loaded": predictor.is_loaded(),
        "device": str(predictor.device),
    }


import asyncio  # ensure asyncio is imported for lifespan

if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host=cfg.server.host,
        port=cfg.server.port,
        reload=True
    )
