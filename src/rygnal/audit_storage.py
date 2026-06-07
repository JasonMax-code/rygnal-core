"""SQLite audit storage backend for Rygnal."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from rygnal.models import AuditEvent


class SQLiteAuditStore:
    """Store and query audit events in a local SQLite database."""

    def __init__(self, db_path: str | Path = "logs/audit_log.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def write_event(self, event: AuditEvent) -> None:
        """Persist one audit event."""
        payload = event.model_dump(mode="json")

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO audit_events (
                    event_id,
                    timestamp,
                    trace_id,
                    user_id,
                    agent_id,
                    environment,
                    tool_name,
                    action,
                    decision,
                    allowed,
                    severity,
                    policy_id,
                    reason,
                    event_hash,
                    payload_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.timestamp,
                    event.trace_id,
                    event.user_id,
                    event.agent_id,
                    event.environment,
                    event.tool_name,
                    event.action,
                    event.decision.value,
                    int(event.allowed),
                    event.severity.value,
                    event.policy_id,
                    event.reason,
                    event.event_hash,
                    json.dumps(payload, sort_keys=True),
                ),
            )

    def read_events(self, limit: int | None = None) -> list[AuditEvent]:
        """Read audit events in insertion order."""
        query = "SELECT payload_json FROM audit_events ORDER BY id ASC"
        params: list[Any] = []

        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()

        return [self._event_from_payload(row["payload_json"]) for row in rows]

    def count_events(self) -> int:
        """Return total stored audit events."""
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM audit_events").fetchone()

        return int(row["count"])

    def get_event(self, event_id: str) -> AuditEvent | None:
        """Return one audit event by event ID."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM audit_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()

        if row is None:
            return None

        return self._event_from_payload(row["payload_json"])

    def find_events(
        self,
        *,
        decision: str | None = None,
        policy_id: str | None = None,
        tool_name: str | None = None,
        allowed: bool | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Find audit events by common indexed fields."""
        where: list[str] = []
        params: list[Any] = []

        if decision is not None:
            where.append("decision = ?")
            params.append(decision)

        if policy_id is not None:
            where.append("policy_id = ?")
            params.append(policy_id)

        if tool_name is not None:
            where.append("tool_name = ?")
            params.append(tool_name)

        if allowed is not None:
            where.append("allowed = ?")
            params.append(int(allowed))

        if severity is not None:
            where.append("severity = ?")
            params.append(severity)

        query = "SELECT payload_json FROM audit_events"

        if where:
            query += " WHERE " + " AND ".join(where)

        query += " ORDER BY id ASC LIMIT ?"
        params.append(limit)

        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()

        return [self._event_from_payload(row["payload_json"]) for row in rows]

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    trace_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    action TEXT,
                    decision TEXT NOT NULL,
                    allowed INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    policy_id TEXT,
                    reason TEXT NOT NULL,
                    event_hash TEXT,
                    payload_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_events_trace_id ON audit_events(trace_id)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_events_policy_id ON audit_events(policy_id)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_events_tool_name ON audit_events(tool_name)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_events_decision ON audit_events(decision)"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _event_from_payload(payload_json: str) -> AuditEvent:
        return AuditEvent(**json.loads(payload_json))
