# SQLite Audit Storage Backend

Rygnal now supports an optional SQLite audit storage backend.

## Goal

Provide a local queryable audit backend while keeping the existing JSONL audit log behavior.

## What Changed

- Added `SQLiteAuditStore`
- Added SQLite table initialization
- Added indexed fields for common audit queries
- Added event insert/read/count/get/find methods
- Added optional `storage_backend` support to `AuditLogger`
- Kept JSONL audit logging as the default behavior

## Why

JSONL is useful for simple local logs and hash-chain validation.

SQLite is useful for local querying, filtering, demos, and future API/dashboard work.

## Current Behavior

`AuditLogger` still writes JSONL events.

If a `SQLiteAuditStore` is passed to `AuditLogger`, the same event is also written to SQLite.

## Example

    from rygnal import AuditLogger, SQLiteAuditStore

    store = SQLiteAuditStore("logs/audit_log.db")
    logger = AuditLogger("logs/audit_log.jsonl", storage_backend=store)

## Query Support

`SQLiteAuditStore` supports:

- `write_event(event)`
- `read_events(limit=None)`
- `count_events()`
- `get_event(event_id)`
- `find_events(...)`

## Not Included Yet

- Postgres backend
- Audit dashboard
- API query endpoint
- Migration system
- Advanced search
