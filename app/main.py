"""
FastAPI application wiring all five security layers around the Azure
OpenAI-backed /chat endpoint. See README.md for the full architecture
write-up; this module intentionally keeps each layer's call site
explicit and in order so the request pipeline is easy to read and to
grade against:

    Layer 1  Authentication            (app/security/auth.py)
    Layer 2  Input validation          (app/security/input_validation.py)
    Layer 3  Rate limiting             (app/security/rate_limit.py)
    Layer 4  Content moderation        (app/security/content_moderation.py)
    Layer 5  Output filtering + audit  (app/security/output_filter.py)
"""
from __future__ import annotations

import time
import uuid

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.azure_client import AzureChatClient
from app.config import Settings, get_settings
from app.logging_config import configure_logging
from app.models import ChatRequest, ChatResponse
from app.security.auth import AuthenticatedUser, require_api_key
from app.security.content_moderation import moderate_text
from app.security.input_validation import validate_and_sanitize
from app.security.output_filter import filter_output, log_audit_event
from app.security.rate_limit import InMemoryRateLimiter

settings = get_settings()
configure_logging(settings)

app = FastAPI(
    title="Azure AI Chatbot - Layered Security Demo",
    description="A chatbot backed by Azure OpenAI, hardened with five independent security layers.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["X-API-Key", "Content-Type"],
)

rate_limiter = InMemoryRateLimiter(
    max_requests=settings.rate_limit_requests,
    window_seconds=settings.rate_limit_window_seconds,
)
azure_client = AzureChatClient(settings)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    return response


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "mock_mode": settings.effective_mock_mode}


@app.post("/chat", response_model=ChatResponse)
async def chat(
    payload: ChatRequest,
    request: Request,
    user: AuthenticatedUser = Depends(require_api_key),
    current_settings: Settings = Depends(get_settings),
) -> ChatResponse:
    request_id = str(uuid.uuid4())
    start = time.perf_counter()

    def _finish(outcome: str, *, injection_flagged=False, mod_in=False, mod_out=False, redactions=None):
        log_audit_event(
            request_id=request_id,
            username=user.username,
            key_fingerprint=user.key_fingerprint,
            input_length=len(payload.message),
            injection_flagged=injection_flagged,
            moderation_input_flagged=mod_in,
            moderation_output_flagged=mod_out,
            redactions=redactions or [],
            outcome=outcome,
            latency_ms=(time.perf_counter() - start) * 1000,
            raw_message=payload.message,
            log_raw_messages=current_settings.log_raw_messages,
        )

    # --- Layer 3: Rate limiting (checked right after auth, before any real work) ---
    rl_result = rate_limiter.check(user.username)
    if not rl_result.allowed:
        _finish("rate_limited")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please slow down.",
            headers={"Retry-After": str(rl_result.retry_after_seconds)},
        )

    # --- Layer 2: Input validation & prompt-injection heuristics ---
    validation = validate_and_sanitize(payload.message, current_settings.max_input_length)
    if not validation.is_valid:
        _finish("input_rejected", injection_flagged=bool(validation.injection_flags))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="; ".join(validation.errors))

    # --- Layer 4: Content moderation (input side) ---
    input_moderation = await moderate_text(validation.sanitized_text, current_settings)
    if input_moderation.flagged:
        _finish("input_blocked_by_moderation", mod_in=True)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your message was blocked by content moderation.",
        )

    # --- Model call ---
    try:
        raw_reply = azure_client.send_message(validation.sanitized_text)
    except Exception as exc:  # noqa: BLE001
        _finish("model_error")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="Upstream model call failed."
        ) from exc

    # --- Layer 4: Content moderation (output side) ---
    output_moderation = await moderate_text(raw_reply, current_settings)
    if output_moderation.flagged:
        _finish("output_blocked_by_moderation", mod_in=False, mod_out=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The generated response was blocked by content moderation.",
        )

    # --- Layer 5: Output filtering (redaction) + audit logging ---
    filtered = filter_output(raw_reply)
    _finish("success", redactions=filtered.redactions)

    return ChatResponse(
        reply=filtered.filtered_text,
        conversation_id=payload.conversation_id,
        request_id=request_id,
        mock_mode=azure_client.mock_mode,
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail}, headers=exc.headers)
