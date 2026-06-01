"""
ViGiL — SQLite Job Store
Replaces the in-memory dict so jobs survive backend restarts.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiosqlite
from loguru import logger

from config import settings

_DB_PATH = Path(settings.reports_dir).parent / "vigil_jobs.db"


async def init_db() -> None:
    """Create tables if they don't exist."""
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                job_id      TEXT PRIMARY KEY,
                filename    TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'queued',
                progress    INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT NOT NULL,
                completed_at TEXT,
                error       TEXT
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                job_id  TEXT PRIMARY KEY,
                data    TEXT NOT NULL,
                saved_at TEXT NOT NULL
            )
        """)
        await db.commit()
    logger.info(f"[DB] SQLite job store at {_DB_PATH}")


async def save_job(job: dict) -> None:
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute("""
            INSERT OR REPLACE INTO jobs
              (job_id, filename, status, progress, created_at, completed_at, error)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            job["job_id"], job["filename"], job["status"],
            job.get("progress", 0), job["created_at"],
            job.get("completed_at"), job.get("error"),
        ))
        await db.commit()


async def update_job(job_id: str, **kwargs) -> None:
    if not kwargs:
        return
    sets = ", ".join(f"{k} = ?" for k in kwargs)
    vals = list(kwargs.values()) + [job_id]
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(f"UPDATE jobs SET {sets} WHERE job_id = ?", vals)
        await db.commit()


async def get_job(job_id: str) -> Optional[dict]:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def list_jobs(limit: int = 100) -> list[dict]:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)
        ) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]


async def save_report(job_id: str, report_json: str) -> None:
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute("""
            INSERT OR REPLACE INTO reports (job_id, data, saved_at)
            VALUES (?, ?, ?)
        """, (job_id, report_json, datetime.now(timezone.utc).isoformat()))
        await db.commit()


async def get_report(job_id: str) -> Optional[dict]:
    async with aiosqlite.connect(_DB_PATH) as db:
        async with db.execute("SELECT data FROM reports WHERE job_id = ?", (job_id,)) as cur:
            row = await cur.fetchone()
            return json.loads(row[0]) if row else None
