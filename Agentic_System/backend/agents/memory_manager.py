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
        """Return a dictionary of memory settings to be passed to CrewAI Crew.

        Parameters
        ----------
        llm:
            The active CrewAI LLM instance to use for memory query analysis.
        crew_name:
            Namespace identifier for memory scoping.

        Returns
        -------
        dict
            Arguments dictionary for Crew initialization containing the custom Memory store.
        """
        from crewai.memory.unified_memory import Memory
        from crewai.rag.embeddings.factory import build_embedder

        active = self.cfg.llm.active_provider
        if active == "openai":
            provider = "openai"
            model = "text-embedding-3-small"
        elif active == "gemini":
            provider = "google"
            model = "models/embedding-001"
        else:
            # Fallback to local HuggingFace embedding to prevent API key issues for non-standard providers
            provider = "huggingface"
            model = "all-MiniLM-L6-v2"

        embedder_cfg = {
            "provider": provider,
            "config": {
                "model": model,
            }
        }
        
        try:
            embedder = build_embedder(embedder_cfg)
        except Exception as exc:
            logger.warning("Failed to build RAG embedder, falling back to None: %s", exc)
            embedder = None

        crew_memory = Memory(
            embedder=embedder,
            llm=llm,  # Use the crew's configured LLM (e.g. nvidia_nim) for query analysis
            root_scope=f"/crew/{crew_name}"
        )

        return {
            "memory": crew_memory
        }
