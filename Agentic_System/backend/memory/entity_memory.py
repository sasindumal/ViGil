"""
ViGil — Entity Memory
=====================

Tracks and correlates indicators of compromise (IOCs) and network entities
across multiple analysis sessions, querying the shared SQLite database.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from backend.memory.long_term import LongTermMemory

logger = logging.getLogger("vigil.memory.entity_memory")


class EntityMemory:
    """Provides methods to correlate and retrieve entities (IPs, domains, hashes) across analyses."""

    def __init__(self):
        self.ltm = LongTermMemory()

    async def track_entity(
        self,
        entity_type: str,
        entity_value: str,
        analysis_id: str,
        context: str,
        threat_level: int = 5
    ):
        """Register or track an entity associated with an analysis session."""
        # This re-uses the LTM iocs table for tracking
        await self.ltm.store_iocs(analysis_id, [{
            "type": entity_type,
            "value": entity_value,
            "context": context,
            "threat_level": threat_level
        }])

    async def get_entity_history(self, entity_type: str, entity_value: str) -> list[dict[str, Any]]:
        """Return list of past analyses where this entity was seen."""
        async with await self.ltm._get_conn() as db:
            async with db.execute(
                "SELECT a.id as analysis_id, a.file_name, a.verdict, a.risk_score, i.context, i.created_at "
                "FROM iocs i JOIN analyses a ON i.analysis_id = a.id "
                "WHERE i.ioc_type = ? AND i.ioc_value = ? "
                "ORDER BY i.created_at DESC",
                (entity_type, entity_value)
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

    async def get_related_entities(self, entity_value: str) -> list[dict[str, Any]]:
        """Find other entities that appeared in the same analyses as *entity_value*."""
        async with await self.ltm._get_conn() as db:
            # First, find all analysis IDs containing entity_value
            async with db.execute(
                "SELECT DISTINCT analysis_id FROM iocs WHERE ioc_value = ?",
                (entity_value,)
            ) as cursor:
                a_rows = await cursor.fetchall()
                analysis_ids = [r["analysis_id"] for r in a_rows]

            if not analysis_ids:
                return []

            # Find all other entities associated with these analysis IDs
            placeholders = ",".join("?" for _ in analysis_ids)
            async with db.execute(
                f"SELECT ioc_type, ioc_value, context, analysis_id "
                f"FROM iocs "
                f"WHERE analysis_id IN ({placeholders}) AND ioc_value != ?",
                (*analysis_ids, entity_value)
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

    async def get_high_risk_entities(self, min_threat_level: int = 7) -> list[dict[str, Any]]:
        """Retrieve all registered entities exceeding a risk threshold."""
        async with await self.ltm._get_conn() as db:
            async with db.execute(
                "SELECT DISTINCT ioc_type, ioc_value, context, threat_level, analysis_id "
                "FROM iocs WHERE threat_level >= ? "
                "ORDER BY threat_level DESC",
                (min_threat_level,)
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]
