"""
ViGil Routes — WebSocket Endpoints
===================================

Manages live client WebSocket subscriptions for streaming analysis progress,
handling both session-specific and global dashboard event channels.
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.core.event_emitter import get_emitter

logger = logging.getLogger("vigil.routes.websocket")

router = APIRouter(tags=["WebSockets"])


@router.websocket("/ws/global")
async def websocket_global(websocket: WebSocket):
    """WebSocket endpoint for global dashboard event streaming."""
    emitter = get_emitter()
    await websocket.accept()
    emitter.subscribe_global(websocket)
    logger.info("Global WebSocket client connected.")

    try:
        while True:
            # Handle incoming client messages (e.g. ping/pong, heartbeat)
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except Exception:
                pass
    except WebSocketDisconnect:
        emitter.unsubscribe_global(websocket)
        logger.info("Global WebSocket client disconnected.")
    except Exception as exc:
        emitter.unsubscribe_global(websocket)
        logger.error("Global WebSocket error: %s", exc)


@router.websocket("/ws/{analysis_id}")
async def websocket_session(websocket: WebSocket, analysis_id: str):
    """WebSocket endpoint for session-specific analysis progress streaming."""
    emitter = get_emitter()
    await websocket.accept()
    
    # 1. Register subscriber
    emitter.subscribe(analysis_id, websocket)
    
    # 2. Push event history (for late joiners or page reloads)
    history = emitter.get_history(analysis_id)
    for event_msg in history:
        try:
            await websocket.send_text(event_msg)
        except Exception:
            break

    logger.info("WebSocket client connected for analysis %s", analysis_id[:8])

    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except Exception:
                pass
    except WebSocketDisconnect:
        emitter.unsubscribe(analysis_id, websocket)
        logger.info("WebSocket client disconnected for analysis %s", analysis_id[:8])
    except Exception as exc:
        emitter.unsubscribe(analysis_id, websocket)
        logger.error("Session WebSocket error for %s: %s", analysis_id[:8], exc)
