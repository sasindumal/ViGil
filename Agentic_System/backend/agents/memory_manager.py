"""
ViGil — CrewAI Memory Manager
==============================

Coordinates memory settings for CrewAI agents, configuring short-term,
long-term, entity, and knowledge base settings.
"""

from __future__ import annotations

import logging
from typing import Any

from backend.config import get_config

logger = logging.getLogger("vigil.agents.memory_manager")


class MemoryManager:
    """Manages memory configuration settings for CrewAI execution."""

    def __init__(self):
        self.cfg = get_config()

    def get_crew_memory_config(self) -> dict[str, Any]:
        """Return a dictionary of memory settings to be passed to CrewAI Crew.

        Returns
        -------
        dict
            Arguments dictionary for Crew initialization.
        """
        # CrewAI supports built-in RAG and SQLite/vector-based memory stores.
        # We enable the default memory system for the Crew.
        return {
            "memory": True,
            "embedder": {
                "provider": "google" if self.cfg.llm.active_provider == "gemini" else "openai",
                "config": {
                    "model": "models/embedding-001" if self.cfg.llm.active_provider == "gemini" else "text-embedding-3-small",
                }
            }
        }
