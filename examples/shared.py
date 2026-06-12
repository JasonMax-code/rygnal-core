"""Shared helpers for Rygnal examples."""

from rygnal import Rygnal, ToolRequest


def build_demo_rygnal(audit_log_path: str) -> Rygnal:
    """Build a demo Rygnal instance with a registered file read handler."""
    rygnal = Rygnal.from_defaults(audit_log_path=audit_log_path)

    def safe_file_read(request: ToolRequest) -> dict[str, str | None]:
        return {
            "target": request.target,
            "content": f"demo content from {request.target}",
        }

    rygnal.register_tool("file_read", safe_file_read)
    return rygnal
