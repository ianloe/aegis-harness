"""Local SQLite state store for tasks, sessions, approvals, and telemetry queue."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    risk_tier TEXT NOT NULL,
    branch TEXT NOT NULL,
    requester TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    active_model TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    model TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    started_at TEXT NOT NULL,
    ended_at TEXT
);

CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,
    requester TEXT NOT NULL,
    approver TEXT NOT NULL,
    risk_tier TEXT NOT NULL,
    decision TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS telemetry_queue (
    event_id TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TEXT NOT NULL,
    delivered_at TEXT
);

CREATE TABLE IF NOT EXISTS checkpoints (
    date_utc TEXT PRIMARY KEY,
    entries_count INTEGER NOT NULL,
    head_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    sent_to_aegis INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
"""


class StateStore:
    """Thin SQLite wrapper for local Harness operational state."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA_SQL)

    def create_task(
        self,
        *,
        task_id: str,
        title: str,
        risk_tier: str,
        branch: str,
        requester: str,
        active_model: Optional[str],
        now_iso: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tasks (task_id, title, risk_tier, branch, requester, status, active_model, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)
                """,
                (task_id, title, risk_tier, branch, requester, active_model, now_iso, now_iso),
            )

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
            return dict(row) if row else None

    def list_tasks(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM tasks ORDER BY created_at DESC").fetchall()
            return [dict(r) for r in rows]

    def set_active_model(self, task_id: str, model: str, now_iso: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE tasks SET active_model = ?, updated_at = ? WHERE task_id = ?",
                (model, now_iso, task_id),
            )

    def create_session(
        self,
        *,
        session_id: str,
        task_id: str,
        actor: str,
        model: Optional[str],
        now_iso: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO sessions (session_id, task_id, actor, model, status, started_at)
                VALUES (?, ?, ?, ?, 'active', ?)
                """,
                (session_id, task_id, actor, model, now_iso),
            )

    def halt_all_sessions(self, now_iso: str) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE sessions SET status = 'killed', ended_at = ? WHERE status = 'active'",
                (now_iso,),
            )
            conn.execute(
                "UPDATE tasks SET status = 'halted', updated_at = ? WHERE status = 'active'",
                (now_iso,),
            )
            return cur.rowcount

    def record_checkpoint(
        self,
        *,
        date_utc: str,
        entries_count: int,
        head_hash: str,
        signature: str,
        created_at: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO checkpoints (date_utc, entries_count, head_hash, signature, sent_to_aegis, created_at)
                VALUES (?, ?, ?, ?, 0, ?)
                """,
                (date_utc, entries_count, head_hash, signature, created_at),
            )

    def record_approval(
        self,
        *,
        task_id: str,
        requester: str,
        approver: str,
        risk_tier: str,
        decision: str,
        notes: Optional[str],
        now_iso: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO approvals (task_id, requester, approver, risk_tier, decision, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (task_id, requester, approver, risk_tier, decision, notes, now_iso),
            )

    def list_approvals(self, task_id: str) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM approvals WHERE task_id = ? ORDER BY created_at ASC",
                (task_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def enqueue_telemetry(
        self,
        *,
        event_id: str,
        endpoint: str,
        payload_json: str,
        created_at: str,
    ) -> bool:
        """Insert a telemetry item idempotently. Returns False if event_id already exists."""
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO telemetry_queue (event_id, endpoint, payload_json, status, attempts, created_at)
                VALUES (?, ?, ?, 'pending', 0, ?)
                """,
                (event_id, endpoint, payload_json, created_at),
            )
            return cur.rowcount > 0

    def pending_telemetry(self, limit: int = 25) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM telemetry_queue
                WHERE status = 'pending'
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def mark_telemetry_delivered(self, event_id: str, delivered_at: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE telemetry_queue
                SET status = 'delivered', attempts = attempts + 1, delivered_at = ?, last_error = NULL
                WHERE event_id = ?
                """,
                (delivered_at, event_id),
            )

    def mark_telemetry_failed(self, event_id: str, error: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE telemetry_queue
                SET attempts = attempts + 1, last_error = ?
                WHERE event_id = ?
                """,
                (error[:500], event_id),
            )

    def telemetry_queue_counts(self) -> Dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS cnt FROM telemetry_queue GROUP BY status"
            ).fetchall()
            return {r["status"]: int(r["cnt"]) for r in rows}
