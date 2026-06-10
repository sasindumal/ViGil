"""
ViGil — Long-Term Memory
=========================

SQLite-backed persistent storage for past analysis records, IOCs, and agent
outputs, utilizing aiosqlite for asynchronous DB transactions.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import aiosqlite

# Import config
from backend.config import get_config

logger = logging.getLogger("vigil.memory.long_term")


class SQLiteContextManager:
    """Custom async context manager for aiosqlite connections to prevent thread reuse errors."""
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn: Optional[aiosqlite.Connection] = None

    async def __aenter__(self) -> aiosqlite.Connection:
        self.conn = await aiosqlite.connect(self.db_path)
        self.conn.row_factory = aiosqlite.Row
        return self.conn

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            await self.conn.close()


class LongTermMemory:
    """Async interface for SQLite-backed threat and analysis persistence."""

    _instance: Optional[LongTermMemory] = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.db_path = get_config().storage.memory_db
        # Ensure parent folder exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    async def _get_conn(self) -> SQLiteContextManager:
        """Return a connection context manager to the SQLite database."""
        return SQLiteContextManager(self.db_path)

    async def init_db(self):
        """Create database tables if they do not exist."""
        logger.info("Initializing SQLite database at %s", self.db_path)
        async with await self._get_conn() as db:
            # Analyses Table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS analyses (
                    id TEXT PRIMARY KEY,
                    file_hash TEXT UNIQUE,
                    file_name TEXT,
                    file_type TEXT,
                    verdict TEXT,
                    confidence REAL,
                    risk_score REAL,
                    full_results_json TEXT,
                    report_markdown TEXT,
                    created_at TEXT
                )
            """)

            # IOCs Table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id TEXT,
                    ioc_type TEXT,
                    ioc_value TEXT,
                    context TEXT,
                    threat_level INTEGER,
                    created_at TEXT,
                    FOREIGN KEY (analysis_id) REFERENCES analyses (id) ON DELETE CASCADE
                )
            """)
            await db.execute("CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs (ioc_value)")

            # Agent Results Table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS agent_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id TEXT,
                    agent_name TEXT,
                    result_json TEXT,
                    created_at TEXT,
                    FOREIGN KEY (analysis_id) REFERENCES analyses (id) ON DELETE CASCADE
                )
            """)
            await db.commit()
        logger.info("SQLite database tables verified.")

    async def store_analysis(
        self,
        analysis_id: str,
        file_hash: str,
        file_name: str,
        file_type: str,
        verdict: str,
        confidence: float,
        risk_score: float,
        results: dict[str, Any],
        report: str
    ) -> str:
        """Persist analysis record.

        Returns
        -------
        str
            The analysis ID.
        """
        now = datetime.now(timezone.utc).isoformat()
        results_str = json.dumps(results, default=str)

        async with await self._get_conn() as db:
            # Check if this hash already exists; if so, we delete or update it
            await db.execute(
                "INSERT OR REPLACE INTO analyses "
                "(id, file_hash, file_name, file_type, verdict, confidence, risk_score, full_results_json, report_markdown, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (analysis_id, file_hash, file_name, file_type, verdict, confidence, risk_score, results_str, report, now)
            )
            await db.commit()
        logger.info("Stored analysis record %s for file %s", analysis_id[:8], file_name)
        return analysis_id

    async def get_analysis(self, analysis_id: str) -> Optional[dict[str, Any]]:
        """Retrieve an analysis record by its ID."""
        async with await self._get_conn() as db:
            async with db.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    d = dict(row)
                    d["full_results_json"] = json.loads(d["full_results_json"])
                    return d
        return None

    async def get_analysis_by_hash(self, file_hash: str) -> Optional[dict[str, Any]]:
        """Look up an analysis record by SHA256 file hash."""
        async with await self._get_conn() as db:
            async with db.execute("SELECT * FROM analyses WHERE file_hash = ?", (file_hash,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    d = dict(row)
                    d["full_results_json"] = json.loads(d["full_results_json"])
                    return d
        return None

    async def get_recent_analyses(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recently processed files."""
        async with await self._get_conn() as db:
            async with db.execute(
                "SELECT id, file_hash, file_name, file_type, verdict, confidence, risk_score, created_at "
                "FROM analyses ORDER BY created_at DESC LIMIT ?",
                (limit,)
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

    async def store_iocs(self, analysis_id: str, iocs: list[dict[str, Any]]):
        """Save a list of parsed IOCs associated with an analysis ID."""
        now = datetime.now(timezone.utc).isoformat()
        async with await self._get_conn() as db:
            for ioc in iocs:
                await db.execute(
                    "INSERT INTO iocs (analysis_id, ioc_type, ioc_value, context, threat_level, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (analysis_id, ioc.get("type"), ioc.get("value"), ioc.get("context"), ioc.get("threat_level", 5), now)
                )
            await db.commit()
        logger.info("Stored %d IOCs for analysis %s", len(iocs), analysis_id[:8])

    async def search_ioc(self, ioc_value: str) -> list[dict[str, Any]]:
        """Find past analyses containing a specific IOC value (e.g. IP/domain)."""
        async with await self._get_conn() as db:
            async with db.execute(
                "SELECT a.id, a.file_name, a.verdict, a.risk_score, i.ioc_type, i.context "
                "FROM iocs i JOIN analyses a ON i.analysis_id = a.id "
                "WHERE i.ioc_value = ?",
                (ioc_value,)
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

    async def store_agent_result(self, analysis_id: str, agent_name: str, result: dict[str, Any]):
        """Persist intermediate or final agent outputs."""
        now = datetime.now(timezone.utc).isoformat()
        res_str = json.dumps(result, default=str)
        async with await self._get_conn() as db:
            await db.execute(
                "INSERT INTO agent_results (analysis_id, agent_name, result_json, created_at) "
                "VALUES (?, ?, ?, ?)",
                (analysis_id, agent_name, res_str, now)
            )
            await db.commit()
        logger.debug("Stored agent result for '%s' in LTM", agent_name)

    async def delete_analysis(self, analysis_id: str):
        """Delete an analysis and all cascading records."""
        async with await self._get_conn() as db:
            await db.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
            await db.commit()
        logger.info("Deleted analysis record %s", analysis_id[:8])
