"""
Layer 5 - Output Filtering, Sensitive-Data Redaction & Audit Logging
=======================================================================
Addresses OWASP LLM02 (Insecure Output Handling) and LLM06 (Sensitive
Information Disclosure).

Two responsibilities:

1. Redaction: before a model reply is returned to the client, scan it for
   patterns that should never leave the server - email addresses, credit
   card-shaped digit sequences, and strings that look like API
   keys/secrets (Azure keys, OpenAI-style "sk-" tokens, generic
   "key=value" secrets). This guards against the model echoing back
   sensitive data it was fed earlier in the conversation, or a
   prompt-injection payload that got past Layer 2 and tricked the model
   into leaking its own configuration.

2. Audit logging: every request is logged as a structured line (timestamp,
   request id, user, layer outcomes, latency) to both stdout and a log
   file, WITHOUT ever writing API keys or (by default) raw message content
   - only lengths/hashes - so the audit trail itself doesn't become a new
   sensitive-data store. Set LOG_RAW_MESSAGES=true only in a controlled,
   non-production environment (e.g. local debugging for this assessment).
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

logger = logging.getLogger("audit")

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")
_SECRET_KEY_RE = re.compile(
    r"\b(sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|(?i:api[_-]?key)\s*[:=]\s*[\'\"]?[A-Za-z0-9/+_-]{16,})"
)


@dataclass
class FilterResult:
    filtered_text: str
    redactions: List[str] = field(default_factory=list)


def filter_output(text: str) -> FilterResult:
    redactions: List[str] = []

    def _redact(pattern: re.Pattern, label: str, value: str) -> str:
        nonlocal redactions
        matches = pattern.findall(value)
        if matches:
            redactions.append(label)
        return pattern.sub(f"[REDACTED-{label}]", value)

    result = text
    result = _redact(_EMAIL_RE, "EMAIL", result)
    result = _redact(_SECRET_KEY_RE, "SECRET", result)
    result = _redact(_CREDIT_CARD_RE, "CARD-NUMBER", result)

    return FilterResult(filtered_text=result, redactions=redactions)


def _hash_preview(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def log_audit_event(
    *,
    request_id: str,
    username: str,
    key_fingerprint: str,
    input_length: int,
    input_hash: str | None = None,
    injection_flagged: bool,
    moderation_input_flagged: bool,
    moderation_output_flagged: bool,
    redactions: List[str],
    outcome: str,
    latency_ms: float,
    raw_message: str | None = None,
    log_raw_messages: bool = False,
) -> None:
    event: Dict[str, Any] = {
        "request_id": request_id,
        "user": username,
        "key_fingerprint": key_fingerprint,
        "input_length": input_length,
        "input_hash": input_hash or (_hash_preview(raw_message) if raw_message else None),
        "injection_flagged": injection_flagged,
        "moderation_input_flagged": moderation_input_flagged,
        "moderation_output_flagged": moderation_output_flagged,
        "redactions": redactions,
        "outcome": outcome,
        "latency_ms": round(latency_ms, 2),
    }
    if log_raw_messages and raw_message is not None:
        event["raw_message"] = raw_message  # opt-in only, never on by default

    logger.info(json.dumps(event, ensure_ascii=False))
