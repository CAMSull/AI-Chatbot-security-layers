"""
Layer 2 - Input Validation & Prompt-Injection Defense
=======================================================
Addresses OWASP LLM01 (Prompt Injection) and general input-handling hygiene.

Two things happen here:

1. Structural validation: length limits, control-character stripping, and
   rejection of empty/whitespace-only input. This is standard defensive
   input handling independent of the fact that the input goes to an LLM.

2. Prompt-injection heuristics: a lightweight pattern scanner that flags
   common jailbreak/override phrasing ("ignore previous instructions",
   "reveal your system prompt", role-override attempts, etc.) so obviously
   malicious input is rejected before it ever reaches the model or costs a
   token.

This heuristic layer is deliberately NOT the only defense against prompt
injection - it is combined with structural isolation of user input in the
model prompt itself (see app/azure_client.py, which wraps user content in
explicit delimiters and instructs the model to treat it as data, not
instructions) and with output-side checks (Layer 5). No single layer is
assumed to be sufficient on its own - this is defense in depth.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Heuristic patterns associated with prompt-injection / jailbreak attempts.
# Not exhaustive - a real deployment would layer this with a classifier
# (e.g. Azure AI Content Safety's Prompt Shields) rather than regex alone.
_INJECTION_PATTERNS = [
    re.compile(r"ignore (all|any|the)?\s*(previous|prior|above) instructions", re.I),
    re.compile(r"disregard (all|any|the)?\s*(previous|prior|above|system)", re.I),
    re.compile(r"reveal (your|the) (system prompt|instructions)", re.I),
    re.compile(r"(show|print|output|repeat) (your|the) (system prompt|instructions)", re.I),
    re.compile(r"you are now (a|an|in)\b", re.I),
    re.compile(r"forget (that )?you (are|were) (an|a) ai", re.I),
    re.compile(r"act as (if you (are|were)|an unrestricted)", re.I),
    re.compile(r"\bdo anything now\b|\bDAN\b"),
    re.compile(r"pretend (you have no|there are no) (restrictions|rules|guidelines)", re.I),
    re.compile(r"<\s*/?system\s*>", re.I),
    re.compile(r"\bsudo\b.*\boverride\b", re.I),
]


@dataclass
class ValidationResult:
    is_valid: bool
    sanitized_text: str = ""
    errors: List[str] = field(default_factory=list)
    injection_flags: List[str] = field(default_factory=list)


def validate_and_sanitize(text: str, max_length: int) -> ValidationResult:
    errors: List[str] = []

    if text is None or not text.strip():
        return ValidationResult(is_valid=False, errors=["Message must not be empty."])

    if len(text) > max_length:
        errors.append(f"Message exceeds maximum length of {max_length} characters.")

    sanitized = _CONTROL_CHARS_RE.sub("", text).strip()

    injection_flags = [pattern.pattern for pattern in _INJECTION_PATTERNS if pattern.search(sanitized)]
    if injection_flags:
        errors.append("Message appears to contain a prompt-injection attempt.")

    return ValidationResult(
        is_valid=not errors,
        sanitized_text=sanitized,
        errors=errors,
        injection_flags=injection_flags,
    )
