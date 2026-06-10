"""
ViGil — Short-Term Memory
==========================

Provides in-memory session-scoped storage for intermediate agent results
and progress tracking. Singleton pattern.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

logger = logging.getLogger("vigil.memory.short_term")


class ShortTermMemory:
    """Session-scoped in-memory storage for active analyses."""

    _instance: Optional[ShortTermMemory] = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        # Dict mapping analysis_id → key-value store
        self._storage: dict[str, dict[str, Any]] = {}
        # Thread-safety lock
        self._lock = asyncio.Lock()

    async def store(self, analysis_id: str, key: str, value: Any):
        """Store a value in session memory."""
        async with self._lock:
            if analysis_id not in self._storage:
                self._storage[analysis_id] = {}
            self._storage[analysis_id][key] = value

    async def retrieve(self, analysis_id: str, key: str) -> Any:
        """Retrieve a key from session memory."""
        async with self._lock:
            return self._storage.get(analysis_id, {}).get(key)

    async def get_all(self, analysis_id: str) -> dict[str, Any]:
        """Get all stored data for an analysis session."""
        async with self._lock:
            return dict(self._storage.get(analysis_id, {}))

    async def store_agent_result(self, analysis_id: str, agent_name: str, result: Any):
        """Helper to store a completed agent's output."""
        async with self._lock:
            if analysis_id not in self._storage:
                self._storage[analysis_id] = {}
            if "agent_results" not in self._storage[analysis_id]:
                self._storage[analysis_id]["agent_results"] = {}
            self._storage[analysis_id]["agent_results"][agent_name] = result

    async def get_agent_results(self, analysis_id: str) -> dict[str, Any]:
        """Retrieve all completed agent results."""
        async with self._lock:
            return dict(self._storage.get(analysis_id, {}).get("agent_results", {}))

    async def clear(self, analysis_id: str):
        """Clear memory for a finished session."""
        async with self._lock:
            self._storage.pop(analysis_id, None)
            logger.info("Cleared short-term memory for session %s", analysis_id[:8])
