from pathlib import Path


def test_sqlite_audit_storage_doc_exists():
    assert Path("docs/32-sqlite-audit-storage.md").exists()


def test_sqlite_audit_storage_doc_mentions_core_behavior():
    content = Path("docs/32-sqlite-audit-storage.md").read_text()

    required_terms = [
        "SQLiteAuditStore",
        "storage_backend",
        "JSONL audit logging",
        "read_events",
        "find_events",
        "Postgres backend",
    ]

    for term in required_terms:
        assert term in content
