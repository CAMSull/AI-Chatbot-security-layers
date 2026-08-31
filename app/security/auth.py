"""
Layer 1 - Authentication & Access Control
==========================================
Every request to a protected endpoint must present a valid API key via the
``X-API-Key`` header. Keys are configured server-side (see app/config.py)
as "raw_key:username" pairs and are never stored or compared in plaintext:
we hash each configured key with SHA-256 at startup and compare the hash of
the incoming key using a constant-time comparison, so this layer is not
vulnerable to timing attacks and a leaked config file doesn't need to store
secrets in the clear either.

This mitigates unauthenticated access to a costly, abusable LLM backend and
gives every downstream layer (rate limiting, audit logging) a stable
identity to key off.
"""
from __future__ import annotations

import hashlib
import hmac
import logging

from fastapi import Header, HTTPException, status

from app.config import get_settings

logger = logging.getLogger("security.auth")


class AuthenticatedUser:
    def __init__(self, username: str, key_fingerprint: str):
        self.username = username
        # Short, non-reversible fingerprint safe to use in logs/rate-limit keys.
        self.key_fingerprint = key_fingerprint


def _hash(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


async def require_api_key(x_api_key: str | None = Header(default=None)) -> AuthenticatedUser:
    settings = get_settings()

    if not x_api_key:
        logger.warning("auth_failed reason=missing_key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header.",
            headers={"WWW-Authenticate": "API-Key"},
        )

    presented_hash = _hash(x_api_key)
    known_keys = settings.api_keys  # {sha256_hex: username}

    matched_username = None
    for known_hash, username in known_keys.items():
        # Constant-time comparison per key to avoid leaking which prefix matched.
        if hmac.compare_digest(presented_hash, known_hash):
            matched_username = username
            break

    if matched_username is None:
        logger.warning("auth_failed reason=invalid_key fingerprint=%s", presented_hash[:12])
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "API-Key"},
        )

    return AuthenticatedUser(username=matched_username, key_fingerprint=presented_hash[:12])
