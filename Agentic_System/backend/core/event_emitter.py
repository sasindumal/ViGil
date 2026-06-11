"""
ViGil — WebSocket Event Emitter

Broadcasts real-time analysis progress events to connected frontend clients.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger("vigil.events")


class EventType(str, Enum):
    # Pipeline lifecycle
    ANALYSIS_STARTED = "analysis_started"
    ANALYSIS_COMPLETED = "analysis_completed"
    ANALYSIS_FAILED = "analysis_failed"

    # Step-level events
    STEP_STARTED = "step_started"
    STEP_PROGRESS = "step_progress"
    STEP_COMPLETED = "step_completed"
    STEP_FAILED = "step_failed"

    # Agent-level events
    AGENT_STARTED = "agent_started"
    AGENT_THINKING = "agent_thinking"
    AGENT_TOOL_USE = "agent_tool_use"
    AGENT_COMPLETED = "agent_completed"
    AGENT_FAILED = "agent_failed"

    # Sub-results
    PE_ANALYSIS_READY = "pe_analysis_ready"
    ML_PREDICTION_READY = "ml_prediction_ready"
    AGENT_RESULT_READY = "agent_result_ready"
    REPORT_READY = "report_ready"

    # File events
    FILE_IDENTIFIED = "file_identified"
    FILES_EXTRACTED = "files_extracted"

    # System
    SYSTEM_STATUS = "system_status"
    LOG = "log"


@dataclass
class AnalysisEvent:
    """A single event emitted during analysis."""
    event_type: EventType
    analysis_id: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    data: Dict[str, Any] = field(default_factory=dict)
    step: Optional[str] = None
    agent: Optional[str] = None
    progress: Optional[float] = None  # 0.0 – 1.0
    message: Optional[str] = None

    def to_json(self) -> str:
        d = {k: v for k, v in asdict(self).items() if v is not None}
        d["event_type"] = self.event_type.value
        return json.dumps(d, default=str)


class EventEmitter:
    """
    Manages WebSocket connections and broadcasts events.

    Usage:
        emitter = EventEmitter()
        emitter.subscribe(analysis_id, websocket)
        await emitter.emit(AnalysisEvent(...))
    """

    def __init__(self):
        # analysis_id → set of websocket connections
        self._subscribers: Dict[str, Set] = {}
        # Global subscribers (admin / dashboard)
        self._global_subscribers: Set = set()
        # Event history per analysis (for late joiners)
        self._history: Dict[str, list] = {}
        self._max_history = 500

    def subscribe(self, analysis_id: str, ws):
        """Subscribe a WebSocket to events for an analysis."""
        if analysis_id not in self._subscribers:
            self._subscribers[analysis_id] = set()
        self._subscribers[analysis_id].add(ws)
        logger.info(f"WS subscribed to analysis {analysis_id[:8]}…")

    def subscribe_global(self, ws):
        """Subscribe to ALL analysis events."""
        self._global_subscribers.add(ws)

    def unsubscribe(self, analysis_id: str, ws):
        if analysis_id in self._subscribers:
            self._subscribers[analysis_id].discard(ws)

    def unsubscribe_global(self, ws):
        self._global_subscribers.discard(ws)

    async def emit(self, event: AnalysisEvent):
        """Broadcast an event to all subscribers of the analysis."""
        msg = event.to_json()
        aid = event.analysis_id

        # Store in history
        if aid not in self._history:
            self._history[aid] = []
        if len(self._history[aid]) < self._max_history:
            self._history[aid].append(msg)

        # Send to analysis-specific subscribers
        targets = list(self._subscribers.get(aid, set())) + list(self._global_subscribers)
        dead = []
        for ws in targets:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(ws)

        # Cleanup dead connections
        for ws in dead:
            self._subscribers.get(aid, set()).discard(ws)
            self._global_subscribers.discard(ws)

        logger.debug(f"Event {event.event_type.value} → {len(targets)-len(dead)} clients")

    async def emit_step(self, analysis_id: str, step: str,
                        event_type: EventType, message: str = "",
                        progress: float = None, data: dict = None):
        """Convenience: emit a step-level event."""
        await self.emit(AnalysisEvent(
            event_type=event_type,
            analysis_id=analysis_id,
            step=step,
            message=message,
            progress=progress,
            data=data or {},
        ))

    async def emit_agent(self, analysis_id: str, agent_name: str,
                         event_type: EventType, message: str = "",
                         data: dict = None):
        """Convenience: emit an agent-level event."""
        await self.emit(AnalysisEvent(
            event_type=event_type,
            analysis_id=analysis_id,
            agent=agent_name,
            message=message,
            data=data or {},
        ))

    def get_history(self, analysis_id: str) -> list:
        """Get event history for late-joining clients."""
        return self._history.get(analysis_id, [])

    def clear_history(self, analysis_id: str):
        self._history.pop(analysis_id, None)


# ── Singleton ─────────────────────────────────────────────────
_emitter: Optional[EventEmitter] = None


def get_emitter() -> EventEmitter:
    global _emitter
    if _emitter is None:
        _emitter = EventEmitter()
    return _emitter
