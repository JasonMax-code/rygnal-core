"""Local FastAPI service for Rygnal Core."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from rygnal.audit_logger import AuditLogger
from rygnal.models import AuditEvent, PolicyDecision, ToolRequest
from rygnal.policy_engine import PolicyEngine, load_default_policy_engine
from rygnal.risk_engine import RiskAssessment, RiskEngine

REDACTED_VALUE = "[REDACTED]"
SECRET_KEYWORDS = {
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "bearer",
    "client_secret",
    "credential",
    "key",
    "password",
    "private_key",
    "secret",
    "token",
}
SECRET_VALUE_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9._-]{8,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b"),
)
INTERNAL_PATH_PATTERN = re.compile(r"(/workspaces/|/home/|/tmp/|[A-Za-z]:\\)")


class EvaluateRequest(BaseModel):
    """Request body for local policy/risk evaluation."""

    tool_name: str
    action: str | None = None
    target: str | None = None
    input: Any | None = None
    user_id: str = "api_user"
    agent_id: str = "api_agent"
    environment: str = "local"
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_tool_request(self) -> ToolRequest:
        """Convert API payload to ToolRequest."""
        return ToolRequest(
            tool_name=self.tool_name,
            action=self.action,
            target=self.target,
            input=self.input,
            user_id=self.user_id,
            agent_id=self.agent_id,
            environment=self.environment,
            metadata=self.metadata,
        )


def create_app(
    *,
    policy_engine: PolicyEngine | None = None,
    risk_engine: RiskEngine | None = None,
    audit_logger: AuditLogger | None = None,
) -> FastAPI:
    """Create the local Rygnal FastAPI app."""
    app = FastAPI(
        title="Rygnal Core Local API",
        version="0.1.0",
        description="Local API for evaluating AI-agent tool actions.",
    )

    active_policy_engine = policy_engine or load_default_policy_engine()
    active_risk_engine = risk_engine or RiskEngine()
    active_audit_logger = audit_logger

    @app.middleware("http")
    async def attach_request_id(request: Request, call_next):  # type: ignore[no-untyped-def]
        request.state.request_id = request.headers.get("X-Request-ID") or f"req_{uuid4().hex}"

        try:
            response = await call_next(request)
        except Exception:
            return api_error_response(
                request=request,
                status_code=500,
                code="internal_server_error",
                message="Internal server error.",
                retryable=True,
                details=None,
            )

        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        return api_error_response(
            request=request,
            status_code=422,
            code="validation_error",
            message="Request validation failed.",
            retryable=False,
            details={"errors": exc.errors()},
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(
        request: Request,
        exc: StarletteHTTPException,
    ) -> JSONResponse:
        return api_error_response(
            request=request,
            status_code=exc.status_code,
            code="http_error",
            message=safe_http_message(exc),
            retryable=False,
            details=None,
        )

    @app.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
        del exc
        return api_error_response(
            request=request,
            status_code=500,
            code="internal_server_error",
            message="Internal server error.",
            retryable=True,
            details=None,
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "rygnal-core"}

    @app.post("/v1/evaluate")
    def evaluate(payload: EvaluateRequest) -> dict[str, Any]:
        request = payload.to_tool_request()
        risk_assessment: RiskAssessment = active_risk_engine.assess(request)
        policy_decision: PolicyDecision = active_policy_engine.evaluate(
            request,
            risk_assessment=risk_assessment,
        )

        audit_event: AuditEvent | None = None
        if active_audit_logger is not None:
            audit_event = active_audit_logger.log_decision(
                request=request,
                policy_decision=policy_decision,
                metadata={
                    "source": "local_fastapi",
                    "risk": risk_assessment.model_dump(mode="json"),
                },
            )

        return redact_for_api(
            {
                "request": request.model_dump(mode="json"),
                "risk_assessment": risk_assessment.model_dump(mode="json"),
                "policy_decision": policy_decision.model_dump(mode="json"),
                "audit_event": audit_event.model_dump(mode="json") if audit_event else None,
            }
        )

    return app


def api_error_response(
    *,
    request: Request,
    status_code: int,
    code: str,
    message: str,
    retryable: bool,
    details: Mapping[str, Any] | None,
) -> JSONResponse:
    """Return a stable, redacted API error response."""
    request_id = getattr(request.state, "request_id", None) or f"req_{uuid4().hex}"

    payload = {
        "error": {
            "code": code,
            "message": message,
            "request_id": request_id,
            "retryable": retryable,
            "details": redact_for_api(details) if details is not None else None,
        }
    }

    return JSONResponse(
        status_code=status_code,
        content=payload,
        headers={"X-Request-ID": request_id},
    )


def safe_http_message(exc: StarletteHTTPException) -> str:
    """Return safe HTTP error text without echoing arbitrary internals."""
    if isinstance(exc, HTTPException) and isinstance(exc.detail, str):
        return redact_text(exc.detail)

    if exc.status_code == 404:
        return "Not found."

    return "HTTP error."


def redact_for_api(value: Any) -> Any:
    """Redact secret-like material before returning local API JSON."""
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if is_sensitive_key(key_text):
                redacted[key_text] = REDACTED_VALUE
            else:
                redacted[key_text] = redact_for_api(item)
        return redacted

    if isinstance(value, list | tuple):
        return [redact_for_api(item) for item in value]

    if isinstance(value, str):
        return redact_text(value)

    return value


def redact_text(value: str) -> str:
    """Redact secret-like strings and local filesystem paths."""
    redacted = value

    for pattern in SECRET_VALUE_PATTERNS:
        redacted = pattern.sub(REDACTED_VALUE, redacted)

    if INTERNAL_PATH_PATTERN.search(redacted):
        return REDACTED_VALUE

    return redacted


def is_sensitive_key(key: str) -> bool:
    """Return true for common credential-bearing key names."""
    normalized = key.lower().replace("-", "_")
    return any(keyword in normalized for keyword in SECRET_KEYWORDS)
