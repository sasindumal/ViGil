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

    def get_crew_memory_config(self, llm: Any, crew_name: str) -> dict[str, Any]:
        """Return memory settings for CrewAI Crew, configured to False for stateless payload analyses."""
        return {
            "memory": False
        }
