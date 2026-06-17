"""Read-only audit query helpers for Rygnal.

This module intentionally does not mutate audit logs. It provides a stable,
API/CLI-friendly query layer over JSONL audit logs with safe malformed-line
handling, bounded pagination, optional lazy integrity verification, and
single-event lookup support.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rygnal.models import AuditEvent
from rygnal.security import redact_sensitive_value


class AuditQueryError(ValueError):
    """Raised when an audit query is invalid."""


@dataclass(frozen=True)
class AuditQuery:
    """Filter and pagination options for read-only audit queries."""

    event_id: str | None = None
    trace_id: str | None = None
    decision: str | None = None
    tool_name: str | None = None
    action: str | None = None
    severity: str | None = None
    policy_id: str | None = None
    since: str | None = None
    until: str | None = None
    limit: int = 100
    offset: int = 0
    max_limit: int = 500
    newest_first: bool = False


@dataclass(frozen=True)
class AuditQueryResult:
    """Stable structured result for audit queries."""

    events: tuple[AuditEvent, ...]
    total_scanned: int
    total_matching: int
    returned_count: int
    malformed_count: int = 0
    warnings: tuple[str, ...] = field(default_factory=tuple)
    limit: int = 100
    offset: int = 0
    newest_first: bool = False
    integrity_verified: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return JSON/API-safe data."""
        return {
            "events": tuple(event.model_dump(mode="json") for event in self.events),
            "total_scanned": self.total_scanned,
            "total_matching": self.total_matching,
            "returned_count": self.returned_count,
            "malformed_count": self.malformed_count,
            "warnings": self.warnings,
            "limit": self.limit,
            "offset": self.offset,
            "newest_first": self.newest_first,
            "integrity_verified": self.integrity_verified,
        }


def query_audit_events(
    source: str | Path | object,
    query: AuditQuery | None = None,
    *,
    verify_integrity: bool = False,
) -> AuditQueryResult:
    """Query audit events from a JSONL path or read-only event source.

    `source` may be:
    - a JSONL path
    - an AuditLogger-like object exposing `log_path`
    - an object exposing `read_events() -> list[AuditEvent]`

    Malformed JSONL lines are skipped and counted instead of raising.
    Integrity verification is opt-in because hash-chain verification may be
    expensive for large logs.
    """

    active_query = _normalize_query(query or AuditQuery())
    _validate_query(active_query)

    events, malformed_count, warnings = _read_audit_events_safely(source)

    since = _parse_optional_timestamp(active_query.since, field_name="since")
    until = _parse_optional_timestamp(active_query.until, field_name="until")

    filtered = [
        event for event in events if _matches_query(event, active_query, since=since, until=until)
    ]

    if active_query.newest_first:
        filtered = list(reversed(filtered))

    page = filtered[active_query.offset : active_query.offset + active_query.limit]
    safe_page = tuple(_redact_event(event) for event in page)

    integrity_verified, integrity_warnings = _verify_integrity_if_requested(
        source,
        verify_integrity=verify_integrity,
    )
    warnings.extend(integrity_warnings)

    return AuditQueryResult(
        events=safe_page,
        total_scanned=len(events),
        total_matching=len(filtered),
        returned_count=len(safe_page),
        malformed_count=malformed_count,
        warnings=tuple(warnings),
        limit=active_query.limit,
        offset=active_query.offset,
        newest_first=active_query.newest_first,
        integrity_verified=integrity_verified,
    )


def _normalize_query(query: AuditQuery) -> AuditQuery:
    if query.limit > query.max_limit:
        return replace(query, limit=query.max_limit)
    return query


def _validate_query(query: AuditQuery) -> None:
    if query.limit < 0:
        raise AuditQueryError("Audit query limit must not be negative.")

    if query.offset < 0:
        raise AuditQueryError("Audit query offset must not be negative.")

    if query.max_limit <= 0:
        raise AuditQueryError("Audit query max_limit must be positive.")


def _read_audit_events_safely(
    source: str | Path | object,
) -> tuple[list[AuditEvent], int, list[str]]:
    """Read audit events without letting one corrupt line fail the whole query."""

    if isinstance(source, str | Path):
        return _read_jsonl_events(Path(source))

    log_path = getattr(source, "log_path", None)
    if log_path is not None:
        return _read_jsonl_events(Path(log_path))

    if hasattr(source, "read_events"):
        return _read_events_from_source(source)

    raise AuditQueryError("Unsupported audit query source.")


def _read_events_from_source(source: object) -> tuple[list[AuditEvent], int, list[str]]:
    try:
        raw_events = source.read_events()  # type: ignore[attr-defined]
    except Exception as exc:
        raise AuditQueryError("Could not read audit events from source.") from exc

    events: list[AuditEvent] = []
    malformed_count = 0

    for event in raw_events:
        if isinstance(event, AuditEvent):
            events.append(event)
        else:
            malformed_count += 1

    warnings = [f"Skipped {malformed_count} malformed audit event(s)."] if malformed_count else []
    return events, malformed_count, warnings


def _read_jsonl_events(path: Path) -> tuple[list[AuditEvent], int, list[str]]:
    if not path.exists():
        return [], 0, []

    events: list[AuditEvent] = []
    malformed_count = 0

    for _line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue

        try:
            payload = json.loads(line)
            events.append(AuditEvent(**payload))
        except Exception:
            malformed_count += 1

    warnings = (
        [f"Skipped {malformed_count} malformed audit log line(s)."] if malformed_count else []
    )
    return events, malformed_count, warnings


def _verify_integrity_if_requested(
    source: str | Path | object,
    *,
    verify_integrity: bool,
) -> tuple[bool | None, list[str]]:
    if not verify_integrity:
        return None, []

    verifier = _resolve_integrity_verifier(source)
    if verifier is None:
        return None, ["Audit integrity verification is unavailable for this source."]

    try:
        return bool(verifier()), []
    except Exception:
        return False, ["Audit integrity verification failed."]


def _resolve_integrity_verifier(source: str | Path | object) -> Callable[[], bool] | None:
    verify_method = getattr(source, "verify_integrity", None)
    if callable(verify_method):
        return verify_method

    return None


def _matches_query(
    event: AuditEvent,
    query: AuditQuery,
    *,
    since: datetime | None,
    until: datetime | None,
) -> bool:
    if query.event_id is not None and event.event_id != query.event_id:
        return False

    if query.trace_id is not None and event.trace_id != query.trace_id:
        return False

    if query.decision is not None and event.decision.value != query.decision:
        return False

    if query.tool_name is not None and event.tool_name != query.tool_name:
        return False

    if query.action is not None and event.action != query.action:
        return False

    if query.severity is not None and event.severity.value != query.severity:
        return False

    if query.policy_id is not None and event.policy_id != query.policy_id:
        return False

    event_time = _parse_optional_timestamp(event.timestamp, field_name="event timestamp")
    if since is not None and event_time is not None and event_time < since:
        return False

    if until is not None and event_time is not None and event_time > until:
        return False

    return True


def _parse_optional_timestamp(value: str | None, *, field_name: str) -> datetime | None:
    if value is None:
        return None

    normalized = value.strip()
    if not normalized:
        raise AuditQueryError(f"Audit query {field_name} must not be blank.")

    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise AuditQueryError(f"Invalid audit query {field_name}.") from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)

    return parsed.astimezone(UTC)


def _redact_event(event: AuditEvent) -> AuditEvent:
    data = event.model_dump(mode="json")
    redacted = redact_sensitive_value(data)

    if not isinstance(redacted, dict):
        raise AuditQueryError("Audit event redaction returned invalid data.")

    return AuditEvent(**redacted)


__all__ = [
    "AuditQuery",
    "AuditQueryError",
    "AuditQueryResult",
    "query_audit_events",
]
